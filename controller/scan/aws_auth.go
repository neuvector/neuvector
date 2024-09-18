package scan

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	awscredentials "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/httpclient"
)

const awsRetryTimes = 3

type awsDriver struct {
	base
}

func (r *awsDriver) Login(cfg *share.CLUSRegistryConfig) (error, string) {
	auth, err := GetAwsEcrAuthToken(cfg.AwsKey, r.proxy)
	if err != nil {
		return err, err.Error()
	}

	r.newRegClient(cfg.Registry, auth.Username, auth.Password)
	r.rc.Alive()
	return nil, ""
}

// --

type awsEcrAuth struct {
	ProxyEndpoint string
	Username      string
	Password      string
	ExpireAt      time.Time
}

func extractToken(token string, proxyEndpoint string) (*awsEcrAuth, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("Invalid token: %v:", err)
	}

	parts := strings.SplitN(string(decodedToken), ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("Invalid token: expected two parts, got %d", len(parts))
	}

	return &awsEcrAuth{
		Username:      parts[0],
		Password:      parts[1],
		ProxyEndpoint: proxyEndpoint,
	}, nil
}

func newClient(proxy string) *http.Client {
	var client http.Client

	t, err := httpclient.GetTransport(proxy)
	if err != nil {
		log.WithError(err).Warn("failed to get transport")
		return nil
	}
	client.Transport = t

	return &client
}

func GetAwsEcrAuthToken(awsKey *share.CLUSAWSAccountKey, proxy string) (*awsEcrAuth, error) {
	client := newClient(proxy)

	conf := aws.NewConfig().WithHTTPClient(client).WithMaxRetries(awsRetryTimes)

	if awsKey.AccessKeyID == "" && awsKey.SecretAccessKey == "" {
		cfg := defaults.Config()
		handlers := defaults.Handlers()

		provd := defaults.RemoteCredProvider(*cfg, handlers)

		conf.Credentials = awscredentials.NewCredentials(provd)
	} else {
		conf.Region = aws.String(awsKey.Region)
		conf.Credentials = awscredentials.NewStaticCredentials(awsKey.AccessKeyID, awsKey.SecretAccessKey, "")
	}

	sess, err := session.NewSession(conf)
	if err != nil {
		return nil, err
	}

	return getAwsEcrAuthTokenById(sess, awsKey.ID, awsKey.Region)
}

func getAwsEcrAuthTokenById(sess *session.Session, registryID, region string) (*awsEcrAuth, error) {
	svc := ecr.New(sess, aws.NewConfig().WithRegion(region))

	// this lets us handle multiple registries
	params := &ecr.GetAuthorizationTokenInput{
		RegistryIds: []*string{aws.String(registryID)},
	}

	// request the token
	resp, err := svc.GetAuthorizationToken(params)
	if err != nil {
		return nil, err
	}

	// multiple auth return, but we only need one
	for _, authData := range resp.AuthorizationData {
		if authData.ProxyEndpoint != nil && authData.AuthorizationToken != nil {
			authorizationToken := aws.StringValue(authData.AuthorizationToken)
			proxyEndpoint := aws.StringValue(authData.ProxyEndpoint)
			expiresAt := aws.TimeValue(authData.ExpiresAt)

			auth, err := extractToken(authorizationToken, proxyEndpoint)
			if err != nil {
				return nil, err
			}
			auth.ExpireAt = expiresAt
			return auth, nil
		}
	}
	return nil, errors.New("No Authorization token found in the response")
}

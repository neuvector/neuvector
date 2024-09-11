package resource

const (
	AwsSvcCloudformation  = "cloudformation"
	AwsSvcCloudWatch      = "cloudwatch"
	AwsSvcCognitoIdentity = "cognito-identity"
	AwsSvcCognitoSync     = "cognito-sync"
	AwsSvcDynamodb        = "dynamodb"
	AwsSvcEc2             = "ec2"
	AwsSvcEvents          = "events"
	AwsSvcIam             = "iam"
	AwsSvcIot             = "iot"
	AwsSvcKinesis         = "kinesis"
	AwsSvcKms             = "kms"
	AwsSvcLambda          = "lambda"
	AwsSvcLogs            = "logs"
	AwsSvcS3              = "s3"
	AwsSvcSns             = "sns"
	AwsSvcSqs             = "sqs"
	AwsSvcTag             = "tag"
	AwsSvcXray            = "xray"
)

// Permession sensitive level
const (
	AwsResHigh = "High"
	AwsResMid  = "Medium"
	AwsResLow  = "Low"
)

const (
	awsPermitLambdaFull = "AWSLambdaFullAccess"
	administratorAccess = "AdministratorAccess"
)

var AwsSvcPolicyMap map[string]string = map[string]string{
	awsPermitLambdaFull: AwsResHigh,
	administratorAccess: AwsResHigh,
}

type AwsSvcResource struct {
	Sensitivity string            `json:"sensitivity"`
	AllowAll    bool              `json:"allow_all"`
	DetailMap   map[string]string `json:"detail_map"`
}

var AwsSvcResMap map[string]AwsSvcResource = map[string]AwsSvcResource{
	AwsSvcCloudformation: {
		Sensitivity: AwsResHigh,
		AllowAll:    false,
		DetailMap: map[string]string{
			"DescribeChangeSet":      AwsResLow,
			"DescribeStackResources": AwsResLow,
			"DescribeStacks":         AwsResLow,
			"GetTemplate":            AwsResLow,
			"ListStackResources":     AwsResLow,
		},
	},
	AwsSvcCloudWatch: {
		Sensitivity: AwsResLow,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcCognitoIdentity: {
		Sensitivity: AwsResHigh,
		AllowAll:    false,
		DetailMap: map[string]string{
			"ListIdentityPools": AwsResLow,
		},
	},
	AwsSvcCognitoSync: {
		Sensitivity: AwsResHigh,
		AllowAll:    false,
		DetailMap: map[string]string{
			"GetCognitoEvents": AwsResLow,
			"SetCognitoEvents": AwsResMid,
		},
	},
	AwsSvcDynamodb: {
		Sensitivity: AwsResHigh,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcEc2: {
		Sensitivity: AwsResHigh,
		AllowAll:    false,
		DetailMap: map[string]string{
			"DescribeSecurityGroups": AwsResLow,
			"DescribeSubnets":        AwsResLow,
			"DescribeVpcs":           AwsResLow,
		},
	},
	AwsSvcEvents: {
		Sensitivity: AwsResLow,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcIam: {
		Sensitivity: AwsResHigh,
		AllowAll:    false,
		DetailMap: map[string]string{
			"GetPolicy":                AwsResLow,
			"GetPolicyVersion":         AwsResLow,
			"GetRole":                  AwsResLow,
			"GetRolePolicy":            AwsResLow,
			"ListAttachedRolePolicies": AwsResLow,
			"ListRolePolicies":         AwsResLow,
			"ListRoles":                AwsResLow,
			"PassRole":                 AwsResMid,
		},
	},
	AwsSvcIot: {
		Sensitivity: AwsResHigh,
		AllowAll:    false,
		DetailMap: map[string]string{
			"AttachPrincipalPolicy":    AwsResMid,
			"AttachThingPrincipal":     AwsResMid,
			"CreateKeysAndCertificate": AwsResMid,
			"CreatePolicy":             AwsResMid,
			"CreateThing":              AwsResMid,
			"CreateTopicRule":          AwsResMid,
			"DescribeEndpoint":         AwsResLow,
			"GetTopicRule":             AwsResLow,
			"ListPolicies":             AwsResLow,
			"ListThings":               AwsResLow,
			"ListTopicRules":           AwsResLow,
			"ReplaceTopicRule":         AwsResMid,
		},
	},
	AwsSvcKinesis: {
		Sensitivity: AwsResMid,
		AllowAll:    false,
		DetailMap: map[string]string{
			"DescribeStream": AwsResLow,
			"ListStreams":    AwsResLow,
			"PutRecord":      AwsResMid,
		},
	},
	AwsSvcKms: {
		Sensitivity: AwsResHigh,
		AllowAll:    false,
		DetailMap: map[string]string{
			"ListAliases": AwsResLow,
		},
	},
	AwsSvcLambda: {
		Sensitivity: AwsResHigh,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcLogs: {
		Sensitivity: AwsResLow,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcS3: {
		Sensitivity: AwsResHigh,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcSns: {
		Sensitivity: AwsResMid,
		AllowAll:    false,
		DetailMap: map[string]string{
			"ListSubscriptions":        AwsResLow,
			"ListSubscriptionsByTopic": AwsResLow,
			"ListTopics":               AwsResLow,
			"Publish":                  AwsResMid,
			"Subscribe":                AwsResMid,
			"Unsubscribe":              AwsResLow,
			"ListQueues":               AwsResLow,
			"SendMessage":              AwsResMid,
		},
	},
	AwsSvcSqs: {
		Sensitivity: AwsResMid,
		AllowAll:    false,
		DetailMap: map[string]string{
			"ListQueues":  AwsResLow,
			"SendMessage": AwsResMid,
		},
	},
	AwsSvcTag: {
		Sensitivity: AwsResLow,
		AllowAll:    false,
		DetailMap: map[string]string{
			"GetResources": AwsResLow,
		},
	},
	AwsSvcXray: {
		Sensitivity: AwsResLow,
		AllowAll:    false,
		DetailMap: map[string]string{
			"PutTelemetryRecords": AwsResLow,
			"PutTraceSegments":    AwsResLow,
		},
	},
}

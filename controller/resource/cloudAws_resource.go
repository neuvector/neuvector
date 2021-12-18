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
	AwsSvcCloudformation: AwsSvcResource{
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
	AwsSvcCloudWatch: AwsSvcResource{
		Sensitivity: AwsResLow,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcCognitoIdentity: AwsSvcResource{
		Sensitivity: AwsResHigh,
		AllowAll:    false,
		DetailMap: map[string]string{
			"ListIdentityPools": AwsResLow,
		},
	},
	AwsSvcCognitoSync: AwsSvcResource{
		Sensitivity: AwsResHigh,
		AllowAll:    false,
		DetailMap: map[string]string{
			"GetCognitoEvents": AwsResLow,
			"SetCognitoEvents": AwsResMid,
		},
	},
	AwsSvcDynamodb: AwsSvcResource{
		Sensitivity: AwsResHigh,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcEc2: AwsSvcResource{
		Sensitivity: AwsResHigh,
		AllowAll:    false,
		DetailMap: map[string]string{
			"DescribeSecurityGroups": AwsResLow,
			"DescribeSubnets":        AwsResLow,
			"DescribeVpcs":           AwsResLow,
		},
	},
	AwsSvcEvents: AwsSvcResource{
		Sensitivity: AwsResLow,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcIam: AwsSvcResource{
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
	AwsSvcIot: AwsSvcResource{
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
	AwsSvcKinesis: AwsSvcResource{
		Sensitivity: AwsResMid,
		AllowAll:    false,
		DetailMap: map[string]string{
			"DescribeStream": AwsResLow,
			"ListStreams":    AwsResLow,
			"PutRecord":      AwsResMid,
		},
	},
	AwsSvcKms: AwsSvcResource{
		Sensitivity: AwsResHigh,
		AllowAll:    false,
		DetailMap: map[string]string{
			"ListAliases": AwsResLow,
		},
	},
	AwsSvcLambda: AwsSvcResource{
		Sensitivity: AwsResHigh,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcLogs: AwsSvcResource{
		Sensitivity: AwsResLow,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcS3: AwsSvcResource{
		Sensitivity: AwsResHigh,
		AllowAll:    true,
		DetailMap:   map[string]string{},
	},
	AwsSvcSns: AwsSvcResource{
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
	AwsSvcSqs: AwsSvcResource{
		Sensitivity: AwsResMid,
		AllowAll:    false,
		DetailMap: map[string]string{
			"ListQueues":  AwsResLow,
			"SendMessage": AwsResMid,
		},
	},
	AwsSvcTag: AwsSvcResource{
		Sensitivity: AwsResLow,
		AllowAll:    false,
		DetailMap: map[string]string{
			"GetResources": AwsResLow,
		},
	},
	AwsSvcXray: AwsSvcResource{
		Sensitivity: AwsResLow,
		AllowAll:    false,
		DetailMap: map[string]string{
			"PutTelemetryRecords": AwsResLow,
			"PutTraceSegments":    AwsResLow,
		},
	},
}

package api

type RESTAwsResDetail struct {
	PermitLeve  string `json:"permission_level"`
	Resource    string `json:"resource"`
	PermitState string `json:"permission_state"`
}

type RESTAwsFuncPermission struct {
	AttachedPolicy bool                          `json:"aws_attached_policy"`
	PolicyLevel    string                        `json:"policy_permission_level"`
	PermitState    []string                      `json:"permission_state"`
	AllowedDetail  map[string][]RESTAwsResDetail `json:"allowed_detail"`
}

type RESTScanAwsFuncDetail struct {
	RESTScanBrief  `json:"scan_brief"`
	RESTScanReport `json:"scan_report"`
}

type RESTScanAwsFuncReport struct {
	FuncID     string                           `json:"function_id"`
	NvSecID    string                           `json:"nv_sec_id"`
	Version    string                           `json:"version"`
	ScanResult RESTScanAwsFuncDetail            `json:"scan_result"`
	AllowedRes map[string]RESTAwsFuncPermission `json:"allowed_resources"` // key: resource_name value: list of func in res
	ReqRes     map[string]RESTAwsFuncPermission `json:"req_resources"`     // key: resource_name value: list of func in res
}

type RESTAwsFunction struct {
	FuncName string                  `json:"function_name"`
	Region   string                  `json:"region"`
	Report   []RESTScanAwsFuncReport `json:"report"`
}

type RESTAwsFuncSummary struct {
	FuncID          string `json:"function_id"`
	Version         string `json:"version"`
	FuncName        string `json:"function_name"`
	ScanResult      string `json:"scan_result"`
	HighVuls        int    `json:"high"`
	MedVuls         int    `json:"medium"`
	PermissionLevel string `json:"permission_level"`
	Status          string `json:"status"`
}

type RESTAwsLambdaResDetail struct {
	Status     string               `json:"status"`
	LambdaFunc []RESTAwsFuncSummary `json:"func_list"`
}

type RESTAwsLambdaRes struct {
	Status       string                             `json:"status"`
	RegionResMap map[string]*RESTAwsLambdaResDetail `json:"aws_region_resource"`
}

type RESTAwsResource struct {
	AccID       string            `json:"acc_id,cloak"`
	AccKey      string            `json:"acc_key,cloak"`
	ProjectName string            `json:"project_name"`
	RegionList  []string          `json:"region_list"`
	ResLambda   *RESTAwsLambdaRes `json:"aws_lambda_resource"`
}

type RESTAwsResourceCreate struct {
	ProjectName string   `json:"project_name"`
	AccID       string   `json:"acc_id,cloak"`
	AccKey      string   `json:"acc_key,cloak"`
	RegionList  []string `json:"region_list,omitempty"`
}

type RESTAwsResourceConfig struct {
	ProjectName string    `json:"project_name"`
	AccID       *string   `json:"acc_id,cloak,omitempty"`
	AccKey      *string   `json:"acc_key,cloak,omitempty"`
	RegionList  *[]string `json:"region_list,omitempty"`
}

type RESTAwsCloudRes struct {
	CloudType   string   `json:"cloud_type"`
	ProjectName string   `json:"project_name"`
	RegionList  []string `json:"region_list"`
	// any new resource add name need start with aws_xxx, other parameter can't use it as UI use aws_xxx to filter
	ResLambda *RESTAwsLambdaRes `json:"aws_lambda_resource"`
}

type RESTCloudResList struct {
	AwsCloudRes []RESTAwsCloudRes `json:"cloud_resources"`
}

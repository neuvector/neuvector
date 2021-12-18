info "3 - Control Plane Configuration"

info "3.1 - Authentication and Authorization"

#todo review
check_3_1_1="3.1.1  - Client certificate authentication should not be used for users (Not Scored)"
output=$(find /etc/kubernetes/static-pod-resources -type f -wholename '*configmaps/client-ca/ca-bundle.crt')
if [ -z "$output" ]; then
  warn "$check_3_1_1"
else
  pass "check_3_1_1"
fi

info "3.2 - Logging"

#todo review with Andson (check recommended audit scripts)
check_3_2_1="3.2.1 - Ensure that a minimal audit policy is created (Scored)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq '.auditConfig.auditFilePath','.auditConfig.enabled','.auditConfig.logFormat','.auditConfig.maximumFileSizeMegabytes','.auditConfig.maximumRetainedFiles')
if [ -z "$output" ]; then
  warn "$check_3_2_1"
else
  pass "$check_3_2_1"
fi

#todo review with Andson (Compliance TBD)
check_3_2_2="3.2.2 - Ensure that the audit policy covers key security concerns (Not Scored)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq '.auditConfig.auditFilePath','.auditConfig.enabled','.auditConfig.logFormat','.auditConfig.maximumFileSizeMegabytes','.auditConfig.maximumRetainedFiles','.auditConfig.policyConfiguration')
if [ -z "$output" ]; then
  warn "$check_3_2_2"
else
  pass "$check_3_2_2"
fi

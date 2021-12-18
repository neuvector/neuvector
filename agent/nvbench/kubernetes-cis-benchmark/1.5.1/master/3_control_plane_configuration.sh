info "3 - Control Plane Configuration"

info "3.1 - Authentication and Authorization"

check_3_1_1="3.1.1  - Client certificate authentication should not be used for users (Not Scored)"
info "$check_3_1_1"
info "        * Review user access to the cluster and ensure that users are not making use of Kubernetes client certificate authentication."

info "3.2 - Logging"

check_3_2_1="3.2.1 - Ensure that a minimal audit policy is created (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--audit-policy-file' >/dev/null 2>&1; then
    auditPolicyFile=$(get_argument_value "$CIS_APISERVER_CMD" '--audit-policy-file')
    pass "$check_3_2_1"
    pass "        * audit-policy-file: $auditPolicyFile"
else
    warn "$check_3_2_1"
fi

check_3_2_2="3.2.2 - Ensure that the audit policy covers key security concerns (Not Scored)"
info "$check_3_2_2"
info "        * Access to Secrets managed by the cluster. Care should be taken to only log Metadata for requests to Secrets, ConfigMaps, and TokenReviews, in order to avoid the risk of logging sensitive data."
info "        * Modification of pod and deployment objects."
info "        * Use of pods/exec, pods/portforward, pods/proxy and services/proxy."

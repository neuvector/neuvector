info "5 - Policies"
info "5.1 - RBAC and Service Accounts"

# Make the loop separator be a new-line in POSIX compliant fashion
set -f; IFS=$'
'

check_5_1_1="5.1.1  - Ensure that the cluster-admin role is only used where required (Not Scored)"
cluster_admins=$(kubectl get clusterrolebindings -o=custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT:.subjects[*].name)
info "$check_5_1_1"
for admin in $cluster_admins; do
 	info "     * $admin"
done

check_5_1_2="5.1.2  - Minimize access to secrets (Not Scored)"
policies=$(kubectl get psp)
info "$check_5_1_2"
for policy in $policies; do
	  info "     * $policy"
done

check_5_1_3="5.1.3  - Minimize wildcard use in Roles and ClusterRoles (Not Scored)"
namespaces=$(kubectl get namespaces)
info "$check_5_1_3"
for namespace in $namespaces; do
	info "     * $namespace"
done

check_5_1_4="5.1.4  - Minimize access to create pods (Not Scored)"
policies=$(kubectl get pods --namespace=kube-system)
info "$check_5_1_4"
for policy in $policies; do
	info "     * $policy"
done

check_5_1_5="5.1.5  - Ensure that default service accounts are not actively used. (Scored)"
secrets=$(kubectl get secrets)
info "$check_5_1_5"
for secret in $secrets; do
	info "     * $secret"
done

#TODO
check_5_1_6="5.1.6  - Ensure that Service Account Tokens are only mounted where necessary (Not Scored)"
info "$check_5_1_6"

info "5.2 - Pod Security Policies"

check_5_2_1="5.2.1  - Minimize the admission of privileged containers (Scored)"
info "$check_5_2_1"

check_5_2_2="5.2.2  - Minimize the admission of containers wishing to share the host process ID namespace (Scored)"
info "$check_5_2_2"

check_5_2_3="5.2.3  - Minimize the admission of containers wishing to share the host IPC namespace (Scored)"
info "$check_5_2_3"

check_5_2_4="5.2.4  - Minimize the admission of containers wishing to share the host network namespace (Scored)"
info "$check_5_2_4"

check_5_2_5="5.2.5  - Minimize the admission of containers with allowPrivilegeEscalation (Scored)"
info "$check_5_2_5"

check_5_2_6="5.2.6  - Minimize the admission of root containers (Scored)"
info "$check_5_2_6"

check_5_2_7="5.2.7  - Minimize the admission of containers with the NET_RAW capability (Scored)"
info "$check_5_2_7"

check_5_2_8="5.2.8  - Minimize the admission of containers with added capabilities (Scored)"
info "$check_5_2_8"

check_5_2_9="5.2.9  - Minimize the admission of containers with capabilities assigned (Scored)"
info "$check_5_2_9"

info "5.3 - Network Policies and CNI"
check_5_3_1="5.3.1  - Ensure that the CNI in use supports Network Policies (Not Scored)"
info "$check_5_3_1"

check_5_3_2="5.3.2  - Ensure that all Namespaces have Network Policies defined (Scored)"
info "$check_5_3_2"

info "5.4 - Secrets Management"
check_5_4_1="5.4.1  - Prefer using secrets as files over secrets as environment variables (Not Scored)"
info "$check_5_4_1"

check_5_4_2="5.4.2  - Consider external secret storage (Not Scored)"
info "$check_5_4_2"

info "5.5 - Extensible Admission Control"
check_5_5_1="5.5.1  - Configure Image Provenance using ImagePolicyWebhook admission controller (Not Scored)"
info "$check_5_5_1"

info "5.6 - General Policies"
check_5_6_1="5.6.1  - Create administrative boundaries between resources using namespaces (Not Scored)"
info "$check_5_6_1"

check_5_6_2="5.6.2  - Ensure that the seccomp profile is set to docker/default in your pod definitions (Not Scored)"
info "$check_5_6_2"

check_5_6_3="5.6.3  - Apply Security Context to Your Pods and Containers (Not Scored)"
info "$check_5_6_3"

check_5_6_4="5.6.4  - The default namespace should not be used (Scored)"
info "$check_5_6_4"

info "5 - Policies"
info "5.1 - RBAC and Service Accounts"

# Make the loop separator be a new-line in POSIX compliant fashion
set -f; IFS=$'
'

check_5_1_1="5.1.1  - Ensure that the cluster-admin role is only used where required (Manual)"
cluster_admins=$(kubectl get clusterrolebindings -o=custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT:.subjects[*].name)
info "$check_5_1_1"
for admin in $cluster_admins; do
 	info "     * $admin"
done

check_5_1_2="5.1.2  - Minimize access to secrets (Manual)"
policies=$(kubectl get psp)
info "$check_5_1_2"
for policy in $policies; do
	  info "     * $policy"
done

check_5_1_3="5.1.3  - Minimize wildcard use in Roles and ClusterRoles (Manual)"
info "$check_5_1_3"

check_5_1_4="5.1.4  - Minimize access to create pods (Manual)"
policies=$(kubectl get pods --namespace=kube-system)
info "$check_5_1_4"
for policy in $policies; do
	info "     * $policy"
done

check_5_1_5="5.1.5  - Ensure that default service accounts are not actively used. (Manual)"
info "check_5_1_5"
info "The default service account should not be used to ensure that rights granted to applications can be more easily audited and reviewed."

#TODO
check_5_1_6="5.1.6  - Ensure that Service Account Tokens are only mounted where necessary (Manual)"
info "$check_5_1_6"
info "Service accounts tokens should not be mounted in pods except where the workload running in the pod explicitly needs to communicate with the API server"

info "5.2 - Pod Security Policies"

check_5_2_1="5.2.1  - Minimize the admission of privileged containers (Manual)"
info "$check_5_2_1"
info "Do not generally permit containers to be run with the securityContext.privileged flag set to true."
check_5_2_2="5.2.2  - Minimize the admission of containers wishing to share the host process ID namespace (Manual)"
info "$check_5_2_2"
info "Do not generally permit containers to be run with the hostPID flag set to true."
check_5_2_3="5.2.3  - Minimize the admission of containers wishing to share the host IPC namespace (Manual)"
info "$check_5_2_3"
info "Do not generally permit containers to be run with the hostIPC flag set to true."
check_5_2_4="5.2.4  - Minimize the admission of containers wishing to share the host network namespace (Manual)"
info "$check_5_2_4"
info "Do not generally permit containers to be run with the hostNetwork flag set to true."
check_5_2_5="5.2.5  - Minimize the admission of containers with allowPrivilegeEscalation (Manual)"
info "$check_5_2_5"
info "Do not generally permit containers to be run with the allowPrivilegeEscalation flag set to true."
check_5_2_6="5.2.6  - Minimize the admission of root containers (Manual)"
info "$check_5_2_6"
info "Do not generally permit containers to be run as the root user."
check_5_2_7="5.2.7  - Minimize the admission of containers with the NET_RAW capability (Manual)"
info "$check_5_2_7"
info "Do not generally permit containers with the potentially dangerous NET_RAW capability."
check_5_2_8="5.2.8  - Minimize the admission of containers with added capabilities (Manual)"
info "$check_5_2_8"
info "Do not generally permit containers with capabilities assigned beyond the default set."
check_5_2_9="5.2.9  - Minimize the admission of containers with capabilities assigned (Manual)"
info "$check_5_2_9"
info "Do not generally permit containers with capabilities"

info "5.3 - Network Policies and CNI"
check_5_3_1="5.3.1  - Ensure that the CNI in use supports Network Policies (Manual)"
info "$check_5_3_1"
info "There are a variety of CNI plugins available for Kubernetes. If the CNI in use does not support Network Policies it may not be possible to effectively restrict traffic in the cluster."
check_5_3_2="5.3.2  - Ensure that all Namespaces have Network Policies defined (Manual)"
info "$check_5_3_2"
info "Use network policies to isolate traffic in your cluster network."

info "5.4 - Secrets Management"
check_5_4_1="5.4.1  - Prefer using secrets as files over secrets as environment variables (Manual)"
info "$check_5_4_1"
info "Kubernetes supports mounting secrets as data volumes or as environment variables. Minimize the use of environment variable secrets."
check_5_4_2="5.4.2  - Consider external secret storage (Manual)"
info "$check_5_4_2"
info "Consider the use of an external secrets storage and management system, instead of using Kubernetes Secrets directly, if you have more complex secret management needs. Ensure the solution requires authentication to access secrets, has auditing of access to and use of secrets, and encrypts secrets. Some solutions also make it easier to rotate secrets."

info "5.5 - Extensible Admission Control"
check_5_5_1="5.5.1  - Configure Image Provenance using image controller configuration parameters (Manual)"
info "$check_5_5_1"
info "Configure Image Provenance for your deployment."

info "5.6 - General Policies"
check_5_6_1="5.6.1  - Create administrative boundaries between resources using namespaces (Manual)"
info "$check_5_6_1"
info "Use namespaces to isolate your Kubernetes objects."
#todo remedition
check_5_6_2="5.6.2  - Ensure that the seccomp profile is set to docker/default in your pod definitions (Manual)"
info "$check_5_6_2"
info "Enable default seccomp profile in your pod definitions."
check_5_6_3="5.6.3  - Apply Security Context to Your Pods and Containers (Manual)"
info "$check_5_6_3"
info "A security context defines the operating system security settings (uid, gid, capabilities, SELinux role, etc..) applied to a container. When designing your containers and pods, make sure that you configure the security context for your pods, containers, and volumes. A security context is a property defined in the deployment yaml. It controls the security parameters that will be assigned to the pod/container/volume. There are two levels of security context: pod level security context, and container level security context."
check_5_6_4="5.6.4  - The default namespace should not be used (Manual)"
info "$check_5_6_4"
info "Resources in a Kubernetes cluster should be segregated by namespace, to allow for security controls to be applied at that level and to make it easier to manage resources."

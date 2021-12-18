info "1.6 - General Security Primitives"

# Make the loop separator be a new-line in POSIX compliant fashion
set -f; IFS=$'
'

check_1_6_1="1.6.1  - Ensure that the cluster-admin role is only used where required(Not Scored)"
cluster_admins=$(kubectl get clusterrolebindings -o=custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT:.subjects[*].name)
info $check_1_6_1
for admin in $cluster_admins; do
 	info "     * $admin"
done

check_1_6_2="1.6.2  - Create Pod Security Policies for your cluster (Not Scored)"
policies=$(kubectl get psp)
info $check_1_6_2
for policy in $policies; do
	  info "     * $policy"
done

check_1_6_3="1.6.3  - Create administrative boundaries between resources using namespaces (Not Scored)"
namespaces=$(kubectl get namespaces)
info $check_1_6_3
for namespace in $namespaces; do
	info "     * $namespace"
done

check_1_6_4="1.6.4  - Create network segmentation using Network Policies (Not Scored)"
policies=$(kubectl get pods --namespace=kube-system)
info $check_1_6_4
for policy in $policies; do
	info "     * $policy"
done

check_1_6_5="1.6.5  - Avoid using Kubernetes Secrets (Not Scored)"
secrets=$(kubectl get secrets)
info $check_1_6_5
for secret in $secrets; do
	info "     * $secret"
done

#TODO
check_1_6_6="1.6.6  - Ensure that the seccomp profile is set to docker/default in your pod definitions (Not Scored)"
info $check_1_6_6
check_1_6_7="1.6.7  - Apply Security Context to Your Pods and Containers (Not Scored)"
info $check_1_6_7
check_1_6_8="1.6.8  - Configure Image Provenance using ImagePolicyWebhook admission controller (Not Scored)"
info $check_1_6_8
check_1_6_9="1.6.9  - Place compensating controls in the form of PSP and RBAC for privileged containers usage"
info $check_1_6_9

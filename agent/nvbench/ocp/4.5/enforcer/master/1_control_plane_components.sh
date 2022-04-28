info "1 - Control Plane Components"

info "1.1 - Master Node Configuration Files"

check_1_1_1="1.1.1  - Ensure that the API server pod specification file permissions are set to 644 or more restrictive (Manual)"

file="/etc/kubernetes/manifests/kube-apiserver-pod.yaml"
if [ -f $file ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_1_1_1"
  else
    warn "$check_1_1_1"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_1"
  info "     * File not found"
fi

check_1_1_2="1.1.2  - Ensure that the API server pod specification file ownership is set to root:root (Manual)"

file="/etc/kubernetes/manifests/kube-apiserver-pod.yaml"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_2"
  else
    warn "$check_1_1_2"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_2"
fi

check_1_1_3="1.1.3  - Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive (Manual)"

file="/etc/kubernetes/manifests/kube-controller-manager-pod.yaml"
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_1_1_3"
  else
    warn "$check_1_1_3"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_3"
  info "     * File not found"
fi

check_1_1_4="1.1.4  - Ensure that the controller manager pod specification file ownership is set to root:root (Manual)"

file="/etc/kubernetes/manifests/kube-controller-manager-pod.yaml"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_4"
  else
    warn "$check_1_1_4"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_4"
fi

check_1_1_5="1.1.5  - Ensure that the scheduler pod specification file permissions are set to 644 or more restrictive (Manual)"

file="/etc/kubernetes/manifests/kube-scheduler-pod.yaml"
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_1_1_5"
  else
    warn "$check_1_1_5"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_5"
  info "     * File not found"
fi

check_1_1_6="1.1.6  - Ensure that the scheduler pod specification file ownership is set to root:root (Manual)"

file="/etc/kubernetes/manifests/kube-scheduler-pod.yaml"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_6"
  else
    warn "$check_1_1_6"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_6"
fi

#todo file name changes to "etcd-pod"
check_1_1_7="1.1.7  - Ensure that the etcd pod specification file permissions are set to 644 or more restrictive (Manual)"

file="/etc/kubernetes/manifests/etcd-pod.yaml"
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_1_1_7"
  else
    warn "$check_1_1_7"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_7"
  info "     * File not found"
fi

check_1_1_8="1.1.8  - Ensure that the etcd pod specification file ownership is set to root:root (Manual)"

file="/etc/kubernetes/manifests/etcd-pod.yaml"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_8"
  else
    warn "$check_1_1_8"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_8"
fi

check_1_1_9="1.1.9  - Ensure that the Container Network Interface file permissions are set to 644 or more restrictive (Manual)"

valid_permission=true
path_cni_netd="/etc/cni/net.d"
path_cni_bin="/opt/cni/bin"
path_cni_multus="/var/run/multus/cni/net.d"
path_sdn_lib_ocpsdn="/var/lib/cni/networks/openshift-sdn"
path_sdn_run_ocpsdn="/var/run/openshift-sdn"
path_ovs_openv="/var/run/openvswitch"
path_ovs_k8s="/var/run/kubernetes"
path_ovs_etc_openv="/etc/openvswitch"
path_ovs_run_openv="/run/openvswitch"
path_ovs_var_openv="/var/run/openvswitch"

invalid_file_list=""

for p in "$path_cni_netd" "$path_cni_bin" "$path_cni_multus" "$path_sdn_lib_ocpsdn" "$path_sdn_run_ocpsdn" "$path_ovs_openv" "$path_ovs_k8s" "$path_ovs_etc_openv" "$path_ovs_run_openv" "$path_ovs_var_openv"
do
  if [ -d "$p" ]; then
    files=$(find $p -type f)
    for i in $files
    do
      if [ $(stat -c %a "$i") -gt 644 ]; then
        valid_permission=false
        invalid_file_list+=" $i"
      fi
    done
  fi
done

if [ "$valid_permission" = "true" ]; then
  pass "$check_1_1_9"
else
  warn "$check_1_1_9"
  for p in $invalid_file_list
  do
    warn " *Wrong ownership for $p "
  done
fi

check_1_1_10="1.1.10  - Ensure that the Container Network Interface file ownership is set to root:root (Manual)"

valid_ownership=true
path_cni_netd="/etc/cni/net.d"
path_cni_bin="/opt/cni/bin"
path_cni_multus="/var/run/multus/cni/net.d"

path_sdn_lib_ocpsdn="/var/lib/cni/networks/openshift-sdn"
path_sdn_run_ocpsdn="/var/run/openshift-sdn"

path_ovs_openv="/var/run/openvswitch"
path_ovs_k8s="/var/run/kubernetes"
path_ovs_etc_openv="/etc/openvswitch"
path_ovs_run_openv="/run/openvswitch"
path_ovs_var_openv="/var/run/openvswitch"

invalid_file_list=""

for p in "$path_cni_netd" "$path_cni_bin" "$path_cni_multus" "$path_sdn_lib_ocpsdn" "$path_sdn_run_ocpsdn"
do
  if [ -d "$p" ]; then
    files=$(find $p -type f)
    for i in $files
    do
      if [ $(stat -c %U:%G "$i") != "root:root" ]; then
        valid_ownership=false
        invalid_file_list+=" $i"
      fi
    done
  fi
done

for p in "$path_ovs_openv" "$path_ovs_k8s" "$path_ovs_etc_openv" "$path_ovs_run_openv" "$path_ovs_var_openv"
do
  if [ -d "$p" ]; then
    files=$(find $p -type f)
    for i in $files
    do
      if [ $(stat -c %U:%G "$i") != "openvswitch:openvswitch" ]; then
        valid_ownership=false
        invalid_file_list+=" $i"
      fi
    done
  fi
done

if [ "$valid_ownership" = "true" ]; then
  pass "$check_1_1_10"
else
  warn "$check_1_1_10"
  for p in $invalid_file_list
  do
    warn " *Wrong ownership for $p "
  done
fi

check_1_1_11="1.1.11  - Ensure that the etcd data directory permissions are set to 700 or more restrictive (Manual)"

file="/var/lib/etcd"
if [ -d "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 700 ]; then
    pass "$check_1_1_11"
  else
    warn "$check_1_1_11"
    warn "     * Wrong permission for $file"
  fi
else
  info "$check_1_1_11"
fi

#todo review
check_1_1_12="1.1.12  - Ensure that the etcd data directory ownership is set to root:root (Manual)"

file="/var/lib/etcd"
if [ -d "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_12"
  else
    warn "$check_1_1_12"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_12"
fi

check_1_1_13="1.1.13  - Ensure that the admin.conf file permissions are set to 644 or more restrictive (Manual)"

file="/etc/kubernetes/kubeconfig"
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -le 644 ]; then
    pass "$check_1_1_13"
  else
    warn "$check_1_1_13"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_13"
  info "     * File not found"
fi

check_1_1_14="1.1.14  - Ensure that the admin.conf file ownership is set to root:root (Manual)"

file="/etc/kubernetes/kubeconfig"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_14"
  else
    warn "$check_1_1_14"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_14"
fi

check_1_1_15="1.1.15  - Ensure that the scheduler.conf file permissions are set to 644 or more restrictive (Manual)"

files=$(find /etc/kubernetes/static-pod-resources -type f -wholename '*/configmaps/scheduler-kubeconfig/kubeconfig')

valid_permission=false
for i in $files
do
  if [ $(stat -c %a "$i") -eq 644 -o $(stat -c %a "$i") -eq 600 -o $(stat -c %a "$i") -eq 400 ]; then
    valid_permission=true
  else
    valid_permission=false
    break
  fi
done

if [ "$valid_permission" = "true" ]; then
  pass "$check_1_1_15"
else
  warn "$check_1_1_15"
fi

check_1_1_16="1.1.16  - Ensure that the scheduler.conf file ownership is set to root:root (Manual)"

files=$(find /etc/kubernetes/static-pod-resources -type f -wholename '*/configmaps/scheduler-kubeconfig/kubeconfig')

valid_permission=false
for i in $files
do
  if [ $(stat -c %u%g "$i") -eq 00 ]; then
    valid_permission=true
  else
    valid_permission=false
    break
  fi
done

if [ "$valid_permission" = "true" ]; then
  pass "$check_1_1_16"
else
  warn "$check_1_1_16"
fi

check_1_1_17="1.1.17  - Ensure that the controller-manager.conf file permissions are set to 644 or more restrictive (Manual)"

files=$(find /etc/kubernetes/static-pod-resources -type f -wholename '*/configmaps/controller-manager-kubeconfig/kubeconfig')

valid_permission=false
for i in $files
do
  if [ $(stat -c %a "$i") -eq 644 -o $(stat -c %a "$i") -eq 600 -o $(stat -c %a "$i") -eq 400 ]; then
    valid_permission=true
  else
    valid_permission=false
    break
  fi
done

if [ "$valid_permission" = "true" ]; then
  pass "$check_1_1_17"
else
  warn "$check_1_1_17"
fi

check_1_1_18="1.1.18  - Ensure that the controller-manager.conf file ownership is set to root:root (Manual)"

files=$(find /etc/kubernetes/static-pod-resources -type f -wholename '*/configmaps/controller-manager-kubeconfig/kubeconfig')

valid_permission=false
for i in $files
do
  if [ $(stat -c %u%g "$i") -eq 00 ]; then
    valid_permission=true
  else
    valid_permission=false
    break
  fi
done

if [ "$valid_permission" = "true" ]; then
  pass "$check_1_1_18"
else
  warn "$check_1_1_18"
fi

check_1_1_19="1.1.19  - Ensure that the Kubernetes PKI directory and file ownership is set to root:root (Manual)"

cert_path="/etc/kubernetes/static-pod-certs"
valid_perm_dir=false
valid_perm_file=false

if [ -f "$cert_path" ]; then

  directories=$(find $cert_path -type d -wholename '*/secrets*')
  files=$(find $cert_path -type f -wholename '*/secrets*')

  for i in $directories
  do
    if [ $(stat -c %u%g "$i") -eq 00 ]; then
      valid_perm_dir=true
    else
      valid_perm_dir=false
      break
    fi
  done

  for i in $files
  do
    if [ $(stat -c %u%g "$i") -eq 00 ]; then
      valid_perm_file=true
    else
      valid_perm_file=false
      break
    fi
  done

  if [ "$valid_perm_file" = "true" ] && [ "$valid_perm_dir" = "true" ]; then
    pass "$check_1_1_19"
  else
    warn "$check_1_1_19"
  fi
else
   warn "$check_1_1_19"
   warn "$cert_path doesn't exist."
fi

check_1_1_20="1.1.20  - Ensure that the Kubernetes PKI certificate file permissions are set to 644 or more restrictive (Manual)"

cert_path="/etc/kubernetes/static-pod-certs"
if [ -f "$cert_path" ]; then
  files=$(find $cert_path -type f -wholename '*/secrets/*.crt')
  valid_perm_file=false
  for i in $files
  do
    if [ $(stat -c %a "$i") -eq 600 ]; then
      valid_perm_file=true
    else
      valid_perm_file=false
      break
    fi
  done

  if [ "$valid_perm_file" = "true" ]; then
    pass "$check_1_1_20"
  else
    warn "$check_1_1_20"
  fi
else
   warn "$check_1_1_20"
   warn "$cert_path doesn't exist."
fi

check_1_1_21="1.1.21  - Ensure that the Kubernetes PKI key file permissions are set to 600 (Manual)"

cert_path="/etc/kubernetes/static-pod-certs"

if [ -f "$cert_path" ]; then
  files=$(find $cert_path -type f -wholename '*/secrets/*.key')
  valid_perm_file=false
  for i in $files
  do
    if [ $(stat -c %a "$i") -eq 600 ]; then
      valid_perm_file=true
    else
      valid_perm_file=false
      break
    fi
  done

  if [ "$valid_perm_file" = "true" ]; then
    pass "$check_1_1_21"
  else
    warn "$check_1_1_21"
  fi
else
   warn "$check_1_1_21"
   warn "$cert_path doesn't exist."
fi

info "1.2 - API Server"

#todo oc
check_1_2_1="1.2.1  - Ensure that anonymous requests are authorized (Manual)"
output_kube=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | \
  jq -r '.data["config.yaml"]' | \
  jq '.auditConfig.policyConfiguration.rules' | \
  grep 'system:unauthenticated' )
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/configmaps/config | \
  jq -r '.data["config.yaml"]' | \
  jq '.auditConfig.policyConfiguration.rules' | \
  grep 'system:unauthenticated' )

if [ -z "$output_kube" ] || [ -z "$output" ]; then
  warn "$check_1_2_1"
else
  pass "$check_1_2_1"
fi

check_1_2_2="1.2.2  - Ensure that the --basic-auth-file argument is not set (Manual)"
output_ocp=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/configmaps/config | grep --color "basic-auth")
output_api=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | grep --color "basic-auth" )
running=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/config.openshift.io/v1/clusteroperators/authentication )
if [ -z "$output_ocp" ] && [ -z "$output_api" ] && [ -n "$running" ] ; then
  pass "$check_1_2_2"
else
  warn "$check_1_2_2"
fi

check_1_2_3="1.2.3  - Ensure that the --token-auth-file parameter is not set (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq '.apiServerArguments //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq '.spec.observedConfig.apiServerArguments //empty')
output_3=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq '.apiServerArguments //empty')
output_4=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/config.openshift.io/v1/clusteroperators/authentication)
if [ -z "$output_1" ] || [ -z "$output_2" ] || [ -z "$output_3" ] || [ -z "$output_4" ]; then
  warn "$check_1_2_3"
else
  pass "$check_1_2_3"
fi

check_1_2_4="1.2.4  - Use https for kubelet connections (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq '.kubeletClientInfo //empty' )
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/secrets/serving-cert )
if [ -z "$output_1" ] || [ -z "$output_2" ]; then
  warn "$check_1_2_4"
else
  pass "$check_1_2_4"
fi

check_1_2_5="1.2.5  - Ensure that the kubelet uses certificates to authenticate (Manual)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq '.kubeletClientInfo //empty' )
if [ -z "$output" ]; then
  warn "$check_1_2_5"
else
  pass "$check_1_2_5"
fi

check_1_2_6="1.2.6  - Verify that the kubelet certificate authority is set as appropriate (Manual)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config  | jq -r '.data["config.yaml"]' | jq '.kubeletClientInfo //empty' )
if [ -z "$output" ]; then
  warn "$check_1_2_6"
else
  pass "$check_1_2_6"
fi

check_1_2_7="1.2.7  - Ensure that the --authorization-mode argument is not set to AlwaysAllow (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config  | jq -r '.data["config.yaml"]' | jq '.apiServerArguments //empty' )
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/configmaps/config  | jq -r '.data["config.yaml"]' | jq '.apiServerArguments //empty' )
output_3=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq '.spec.observedConfig.apiServerArguments //empty' )
if [ -z "$output_1" ] || [ -z "$output_2" ] || [ -z "$output_3" ]; then
  warn "$check_1_2_7"
else
  pass "$check_1_2_7"
fi

check_1_2_8="1.2.8  - Verify that the Node authorizer is enabled (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq '.apiServerArguments //empty' )
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq '.apiServerArguments //empty' )
output_3=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq '.spec.observedConfig.apiServerArguments //empty' )
if [ -z "$output_1" ] || [ -z "$output_2" ] || [ -z "$output_3" ]; then
  warn "$check_1_2_8"
else
  pass "$check_1_2_8"
fi

check_1_2_9="1.2.9  - Verify that RBAC is enabled (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq '.apiServerArguments //empty' )
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq '.apiServerArguments //empty' )
if [ -z "$output_1" ] || [ -z "$output_2" ]; then
  warn "$check_1_2_9"
else
  pass "$check_1_2_9"
fi

check_1_2_10="1.2.10  - Ensure that the APIPriorityAndFairness feature gate is enabled (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data."config.yaml"' | jq '.apiServerArguments."enable-admission-plugins" //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq -r '.spec.unsupportedConfigOverrides //empty')
if [ -z "$output_1" ] && [ -z "$output_2" ]; then
    pass "$check_1_2_10"
else
    warn "$check_1_2_10"
fi

check_1_2_11="1.2.11  - Ensure that the admission control plugin AlwaysAdmit is not set (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data."config.yaml"' | jq '.apiServerArguments."enable-admission-plugins" //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq -r '.spec.unsupportedConfigOverrides //empty')
if [ -z "$output_1" ] && [ -z "$output_2" ]; then
    pass "$check_1_2_11"
else
    warn "$check_1_2_11"
fi

check_1_2_12="1.2.12  - Ensure that the admission control plugin AlwaysPullImages is set (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data."config.yaml"' | jq '.apiServerArguments."enable-admission-plugins" //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq -r '.spec.unsupportedConfigOverrides //empty')
if [ -z "$output_1" ] && [ -z "$output_2" ]; then
    pass "$check_1_2_12"
else
    warn "$check_1_2_12"
fi

check_1_2_13="1.2.13  - Ensure that the admission control plugin SecurityContextDeny is not set (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data."config.yaml"' | jq '.apiServerArguments."enable-admission-plugins" //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq -r '.spec.unsupportedConfigOverrides //empty')
output_3=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/security.openshift.io/v1/securitycontextconstraints/restricted | grep "SecurityContextDeny")
output_4=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/security.openshift.io/v1/securitycontextconstraints/restricted  | grep 'Allow Privileged:'| grep false)
if [ -z "$output_1" ] && [ -z "$output_2" ] && [ -z "$output_3" ] && [ -n "$output_4" ]; then
    pass "$check_1_2_13"
else
    warn "$check_1_2_13"
fi

check_1_2_14="1.2.14  - Ensure that the admission control plugin ServiceAccount is set (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data."config.yaml"' | jq '.apiServerArguments."enable-admission-plugins" //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq -r '.spec.unsupportedConfigOverrides //empty')
if [ -z "$output_1" ] && [ -z "$output_2" ]; then
    pass "$check_1_2_14"
else
    warn "$check_1_2_14"
fi

#todo review with Andson "Verify that NamespaceLifecycle is in place"
check_1_2_15="1.2.15  - Ensure that the admission control plugin NamespaceLifecycle is set (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data."config.yaml"' | jq '.apiServerArguments."enable-admission-plugins" //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq -r '.spec.unsupportedConfigOverrides //empty')
if [ -z "$output_1" ] && [ -z "$output_2" ]; then
    pass "$check_1_2_15"
else
    warn "$check_1_2_15"
fi

#todo the same audit script as 1.2.13
check_1_2_16="1.2.16  - Ensure that the admission control plugin SecurityContextConstraint is set (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data."config.yaml"' | jq '.apiServerArguments."enable-admission-plugins" //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq -r '.spec.unsupportedConfigOverrides //empty')
output_3=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/security.openshift.io/v1/securitycontextconstraints/restricted | grep "SecurityContextDeny")
output_4=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/security.openshift.io/v1/securitycontextconstraints/restricted | grep 'Allow Privileged:'| grep false)
if [ -z "$output_1" ] && [ -z "$output_2" ] && [ -z "$output_3" ] && [ -n "$output_4" ]; then
    pass "$check_1_2_16"
else
    warn "$check_1_2_16"
fi

#todo reivew with Andson "need a command to verify NodeRestriction"
check_1_2_17="1.2.17  - Ensure that the admission control plugin NodeRestriction is set (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data."config.yaml"' | jq '.apiServerArguments."enable-admission-plugins"  //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq -r '.spec.unsupportedConfigOverrides //empty')
if [ -z "$output_1" ] && [ -z "$output_2" ]; then
    pass "$check_1_2_17"
else
    warn "$check_1_2_17"
fi

check_1_2_18="1.2.18  - Ensure that the --insecure-bind-address argument is not set (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq '.spec.observedConfig' | grep bind)
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/kube-apiserver-pod | grep --color "insecure-bind-address")

if [ -n "$output_1" ] && [ -z "$output_2" ]; then
  pass "$check_1_2_18"
else
  warn "$check_1_2_18"
fi

#todo review with Andson "insecure-port"
check_1_2_19="1.2.19  - Ensure that the --insecure-port argument is set to 0 (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq '.spec.observedConfig' | grep insecure)
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/kube-apiserver-pod | grep --color "insecure-port")
if [ -z "$output" ] && [ -n "$output_2" ]; then
  pass "$check_1_2_19"
else
  warn "$check_1_2_19"
fi

check_1_2_20="1.2.20  - Ensure that the --secure-port argument is not set to 0 (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq '.spec.observedConfig //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | grep --color "bindAddress")
if [ -z "$output_1" ] || [ -z "$output_2" ]; then
  warn "$check_1_2_20"
else
  pass "$check_1_2_20"
fi

#todo review by Andson "default port value 10248, bindAddress is 127.0.0.1"
check_1_2_21="1.2.21  - Ensure that the healthz endpoint is protected by RBAC (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq '.spec.observedConfig.apiServerArguments //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/kube-apiserver-pod | grep --color healthz)
output_3=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/endpoints/api)
if [ -n "$output_1" ] && [ -n "$output_2" ] && [ -n "$output_3" ]; then
  pass "$check_1_2_21"
else
  warn "$check_1_2_21"
fi

check_1_2_22="1.2.22  - Ensure that the --audit-log-path argument is set (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq '.spec.observedConfig.apiServerArguments')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.auditConfig.auditFilePath //empty')
output_3=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.auditConfig.auditFilePath //empty')
if [ -z "$output_1" ] || [ -z "$output_2" ] || [ -z "$output_3" ]; then
    warn "$check_1_2_22"
else
    pass "$check_1_2_22"
fi

check_1_2_23="1.2.23  - Ensure that the audit logs are forwarded off the cluster for retention (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster | jq '.spec.observedConfig //empty')
if [ -n "$output_1" ]; then
  pass "$check_1_2_23"
else
  warn "$check_1_2_23"
fi

check_1_2_24="1.2.24  - Ensure that the maximumRetainedFiles argument is set to 10 or as appropriate (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.auditConfig.maximumRetainedFiles //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.auditConfig.maximumRetainedFiles //empty')
if [ "$output_1" -eq 10 -a "$output_2" -eq 10 ] > /dev/null 2>&1; then
  pass "$check_1_2_24"
else
  warn "$check_1_2_24"
fi

check_1_2_25="1.2.25  - Ensure that the maximumFileSizeMegabytes argument is set to 100 or as appropriate (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.auditConfig.maximumFileSizeMegabytes //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.auditConfig.maximumFileSizeMegabytes //empty')
if [ "$output_1" -eq 100 -a "$output_2" -eq 100 ] > /dev/null 2>&1; then
  pass "$check_1_2_25"
else
  warn "$check_1_2_25"
fi

check_1_2_26="1.2.26  - Ensure that the --request-timeout argument is set as appropriate (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.servingInfo.requestTimeoutSeconds //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.servingInfo.requestTimeoutSeconds //empty')
if [ "$output_1" -eq 3600 -a -z "$output_2" ]; then
  pass "$check_1_2_26"
else
  warn "$check_1_2_26"
fi

#todo review with Andson
check_1_2_27="1.2.27  - Ensure that the --service-account-lookup argument is set to true (Manual)"
info "$check_1_2_27
      OpenShift denies access for any OAuth Access token that does not exist in its etcd data store.
      OpenShift does not use the service-account-lookup flag."

check_1_2_28="1.2.28  - Ensure that the --service-account-key-file argument is set as appropriate (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.serviceAccountPublicKeyFiles //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.serviceAccountPublicKeyFiles //empty')
if [ -z "$output_1" ] || [ -z "$output_2" ]; then
  warn "$check_1_2_28"
else
  pass "$check_1_2_28"
fi

check_1_2_29="1.2.29  - Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate (Manual)"
output_cert=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.storageConfig.certFile //empty')
output_key=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.storageConfig.keyFile //empty')
if [ -z "$output_cert" ] || [ -z "$output_key" ]; then
  warn "$check_1_2_29"
else
  pass "$check_1_2_29"
fi

check_1_2_30="1.2.30  - Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Manual)"
output_cert=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.servingInfo.certFile //empty')
output_key=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.servingInfo.keyFile //empty')
if [ -z "$output_cert" ] || [ -z "$output_key" ]; then
  warn "$check_1_2_30"
else
  pass "$check_1_2_30"
fi

check_1_2_31="1.2.31  - Ensure that the --client-ca-file argument is set as appropriate (Manual)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.servingInfo.clientCA //empty')
if [ -z "$output" ]; then
  warn "$check_1_2_31"
else
  pass "$check_1_2_31"
fi

check_1_2_32="1.2.32  - Ensure that the --etcd-cafile argument is set as appropriate (Manual)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-apiserver/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.storageConfig.ca //empty')
if [ -z "$output" ]; then
  warn "$check_1_2_32"
else
  pass "$check_1_2_32"
fi

#todo review with Andson
check_1_2_33="1.2.33  - Ensure that the --encryption-provider-config argument is set as appropriate (Manual)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/openshiftapiservers/cluster -o=jsonpath='{range .items[0].status.conditions[?(@.type=="Encrypted")]}{.reason}{"\n"}{.message}{"\n"}')
if [ -z "$output" ]; then
  warn "$check_1_2_33"
else
  pass "$check_1_2_33"
fi
#if get_argument_value "$CIS_APISERVER_CMD" '--encryption-provider-config'| grep 'EncryptionConfig' >/dev/null 2>&1; then
#    pass "$check_1_2_33"
#else
#    warn "$check_1_2_33"
#fi

#todo review with Andson
check_1_2_34="1.2.34  - Ensure that encryption providers are appropriately configured (Manual)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/openshiftapiservers/cluster -o=jsonpath='{range .items[0].status.conditions[?(@.type=="Encrypted")]}{.reason}{"\n"}{.message}{"\n"}')
if [ -z "$output" ]; then
  warn "$check_1_2_34"
else
  pass "$check_1_2_34"
fi
#if check_argument "$CIS_APISERVER_CMD" '--encryption-provider-config' >/dev/null 2>&1; then
#    encryptionConfig=$(get_argument_value "$CIS_APISERVER_CMD" '--encryption-provider-config')
#    if [ -f "$encryptionConfig" ]; then
#      if [ $(grep -c "\- aescbc:\|\- kms:\|\- secretbox:" $encryptionConfig) -ne 0 ]; then
#        pass "$check_1_2_34"
#      else
#        warn "$check_1_2_34"
#      fi
#    else
#      warn "$check_1_2_34"
#    fi
#else
#    warn "$check_1_2_34"
#fi
#if get_argument_value "$CIS_APISERVER_CMD" '--experimental-encryption-provider-config'| grep 'EncryptionConfig' >/dev/null 2>&1; then
#    encryptionConfig=$(get_argument_value "$CIS_APISERVER_CMD" '--experimental-encryption-provider-config')
#    if sed ':a;N;$!ba;s/\n/ /g' $encryptionConfig |grep "providers:\s* - aescbc" >/dev/null 2>&1; then
#        pass "$check_1_2_34"
#    else
#        warn "$check_1_2_34"
#    fi
#else
#    warn "$check_1_2_34"
#fi

#todo review with Andson
check_1_2_35="1.2.35  - Ensure that the API Server only makes use of Strong Cryptographic Ciphers (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-authentication/configmaps/v4-0-config-system-cliconfig -o jsonpath='{.data.v4\-0\-config\-system\-cliconfig}' | jq '.servingInfo //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/kubeapiservers/cluster |jq '.spec.observedConfig.servingInfo //empty')
output_3=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/openshiftapiservers/cluster |jq '.spec.observedConfig.servingInfo //empty')
output_3=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/apis/operator.openshift.io/v1/namespaces/openshift-ingress-operator/ingresscontrollers/default )

if [ -z "$output_1" ] || [ -z "$output_2" ] || [ -z "$output_3" ] || [ -z "$output_4" ]; then
  warn "$check_1_2_35"
else
  pass "$check_1_2_35"
fi

info "1.3 - Controller Manager"

#todo review with Andson
check_1_3_1="1.3.1  - Ensure that garbage collection is configured as appropriate (Manual)"
info "$check_1_3_1"
info "Garbage collection is important to ensure sufficient resource availability and avoiding degraded performance and availability. In the worst case, the system might crash or just be unusable for a long period of time. The current setting for garbage collection is 12,500 terminated pods which might be too high for your system to sustain. Based on your system resources and tests, choose an appropriate threshold value to activate garbage collection."


## Filter out processes like "/bin/tee -a /var/log/kube-controller-manager.log"
## which exist on kops-managed clusters.
#if check_argument "$CIS_MANAGER_CMD" '--terminated-pod-gc-threshold' >/dev/null 2>&1; then
#    threshold=$(get_argument_value "$CIS_MANAGER_CMD" '--terminated-pod-gc-threshold')
#    pass "$check_1_3_1"
#    pass "       * terminated-pod-gc-threshold: $threshold"
#else
#    warn "$check_1_3_1"
#fi

check_1_3_2="1.3.2  - Ensure that controller manager healthz endpoints are protected by RBAC (Manual)"

info "$check_1_3_2"
info "Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface."
#if check_argument "$CIS_MANAGER_CMD" '--profiling=false' >/dev/null 2>&1; then
#    pass "$check_1_3_2"
#else
#    warn "$check_1_3_2"
#fi

check_1_3_3="1.3.3  - Ensure that the --use-service-account-credentials argument is set to true (Manual)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-controller-manager/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.extendedArguments["use-service-account-credentials"]' | grep true)
if [ -n "$output" ]; then
  pass "$check_1_3_3"
else
  warn "$check_1_3_3"
fi

check_1_3_4="1.3.4  - Ensure that the --service-account-private-key-file argument is set as appropriate (Manual)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-controller-manager/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.extendedArguments["service-account-private-key-file"] //empty')
if [ -z "$output" ]; then
  warn "$check_1_3_4"
else
  pass "$check_1_3_4"
fi

check_1_3_5="1.3.5  - Ensure that the --root-ca-file argument is set as appropriate (Manual)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-controller-manager/configmaps/config | jq -r '.data["config.yaml"]' | jq -r '.extendedArguments["root-ca-file"] //empty')
if [ -z "$output" ]; then
  warn "$check_1_3_5"
else
  pass "$check_1_3_5"
fi

check_1_3_6="1.3.6  - Ensure that the RotateKubeletServerCertificate argument is set to true (Manual)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-controller-manager/configmaps/config | jq -r '.data["config.yaml"]' | jq '.extendedArguments["feature-gates"]' | grep "RotateKubeletServerCertificate=true")
if [ -z "$output" ]; then
  warn "$check_1_3_6"
else
  pass "$check_1_3_6"
fi


check_1_3_7="1.3.7  - Ensure that the --bind-address argument is set to 127.0.0.1 (Manual)"
output_1=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-controller-manager/configmaps/config | jq -r '.data["config.yaml"]' | jq '.extendedArguments["secure-port"] //empty')
output_2=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-controller-manager/configmaps/config | jq -r '.data["config.yaml"]' | jq '.extendedArguments["port"] //empty')
if [ -z "$output_1" ] || [ -z "$output_2" ]; then
  warn "$check_1_3_7"
else
  pass "$check_1_3_7"
fi

info "1.4 - Scheduler"

#todo not implemented
check_1_4_1="1.4.1  - Ensure that the healthz endpoints for the scheduler are protected by RBAC (Manual)"
info "$check_1_4_1"
info "Disable profiling, if not needed."
#if check_argument "$CIS_SCHEDULER_CMD" '--profiling=false' >/dev/null 2>&1; then
#  	pass "$check_1_4_1"
#else
#  	warn "$check_1_4_1"
#fi

#todo review
check_1_4_2="1.4.2  - Verify that the scheduler API service is protected by authentication and authorization (Manual)"
output=$(curl -ks -H "Authorization: Bearer $OC_TOKEN" https://kubernetes.default/api/v1/namespaces/openshift-kube-scheduler/configmaps/config | jq -r '.data["config.yaml"]' | jq '.extendedArguments["secure-port"] //empty' )
if [ -z "$output" ]; then
  pass "$check_1_4_2"
else
  warn "$check_1_4_2"
fi
#if get_argument_value "$CIS_SCHEDULER_CMD" '--bind-address'| grep '127.0.0.1' >/dev/null 2>&1; then
#  	pass "$check_1_4_2"
#else
#  	warn "$check_1_4_2"
#fi
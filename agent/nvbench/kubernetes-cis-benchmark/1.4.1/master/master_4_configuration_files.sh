info "1.4 - Configuration Files"

check_1_4_1="1.4.1  - Ensure that the API server pod specification file permissions are set to 644 or more restrictive (Scored)"
config_json=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/kube-apiserver.json")
config_manifest=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/kube-apiserver.manifest")
config_yaml=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/kube-apiserver.yaml")
if [ -f $config_json ]; then
    # kops
    file=$config_json
elif [ -f $config_manifest ]; then
    # kops
    file=$config_manifest
else
    file=$config_yaml
fi

if [ -f $file ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_1_4_1"
  else
    warn "$check_1_4_1"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_4_1"
  info "     * File not found"
fi

check_1_4_2="1.4.2  - Ensure that the API server pod specification file ownership is set to root:root (Scored)"
if [ -f $file ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_4_2"
  else
    warn "$check_1_4_2"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_4_2"
fi

check_1_4_3="1.4.3  - Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive (Scored)"
config_json=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/kube-controller-manager.json")
config_manifest=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/kube-controller-manager.manifest")
config_yaml=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/kube-controller-manager.yaml")
if [ -f $config_json ]; then
    # kops
    file=$config_json
elif [ -f $config_manifest ]; then
    # kops
    file=$config_manifest
else
    file=$config_yaml
fi

if [ -f $file ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_1_4_3"
  else
    warn "$check_1_4_3"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_4_3"
  info "     * File not found"
fi

check_1_4_4="1.4.4  - Ensure that the controller manager pod specification file ownership is set to root:root (Scored)"
if [ -f $file ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_4_4"
  else
    warn "$check_1_4_4"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_4_4"
  info "     * File not found"
fi

check_1_4_5="1.4.5  - Ensure that the scheduler pod specification file permissions are set to 644 or more restrictive (Scored)"
config_json=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/kube-scheduler.json")
config_manifest=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/kube-scheduler.manifest")
config_yaml=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/kube-scheduler.yaml")
if [ -f $config_json ]; then
    # kops
    file=$config_json
elif [ -f $config_manifest ]; then
    file=$config_manifest
else
    file=$config_yaml
fi

if [ -f $file ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_1_4_5"
  else
    warn "$check_1_4_5"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_4_5"
  info "     * File not found"
fi

check_1_4_6="1.4.6  - Ensure that the scheduler pod specification file ownership is set to root:root (Scored)"
if [ -f $file ]; then
  if [ "$(stat -c %U:%G $file)" = "root:root" ]; then
    pass "$check_1_4_6"
  else
    warn "$check_1_4_6"
    owner=$(stat -c %U:%G $file)
    warn "     * Wrong ownership for $file:$owner"
  fi
else
  info "$check_1_4_6"
  info "     * File not found"
fi

check_1_4_7="1.4.7  - Ensure that the etcd pod specification file permissions are set to 644 or more restrictive (Scored)"
config_json=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/etcd.json")
config_manifest=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/etcd.manifest")
config_yaml=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/manifests/etcd.yaml")
if [ -f $config_json ]; then
    # kops
    file=$config_json
elif [ -f $config_manifest ]; then
    # kops
    # Also this file is a symlink, hence 'stat -L' below.
    file=$config_manifest
else
    file=$config_yaml
fi

if [ -f $file ]; then
  if [ "$(stat -L -c %a $file)" -eq 644 -o "$(stat -L -c %a $file)" -eq 640 -o "$(stat -L -c %a $file)" -eq 600 ]; then
    pass "$check_1_4_7"
  else
    warn "$check_1_4_7"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_4_7"
  info "     * File not found"
fi

check_1_4_8="1.4.8  - Ensure that the etcd pod specification file ownership is set to root:root (Scored)"
if [ -f $file ]; then
  if [ "$(stat -c %U:%G $file)" = "root:root" ]; then
    pass "$check_1_4_8"
  else
    warn "$check_1_4_8"
    owner=$(stat -c %U:%G $directory)
    warn "     * Wrong ownership for $file:$owner"
  fi
else
  info "$check_1_4_8"
fi

#TODO
check_1_4_9="1.4.9  - Ensure that the Container Network Interface file permissions are set to 644 or more restrictive (Not Scored)"
info "$check_1_4_9"

check_1_4_10="1.4.10  - Ensure that the Container Network Interface file ownership is set to root:root (Not Scored)"
info "$check_1_4_10"

check_1_4_11="1.4.11  - Ensure that the etcd data directory permissions are set to 700 or more restrictive (Scored)"
directory=$(get_argument_value "$CIS_ETCD_CMD" '--data-dir')
if [ -d "$directory" ]; then
  if [ "$(stat -c %a $directory)" -eq 700 ]; then
    pass "$check_1_4_11"
  else
    warn "$check_1_4_11"
    perm=$(stat -c %a $directory)
    warn "     * Wrong permissions for $directory:$perm"
  fi
else
  warn "$check_1_4_11"
  warn "     * Directory not found:$directory"
fi

check_1_4_12="1.4.12  - Ensure that the etcd data directory ownership is set to etcd:etcd (Scored)"
directory=$(get_argument_value "$CIS_ETCD_CMD" '--data-dir')
if [ -d "$directory" ]; then
  if [ "$(stat -c %U:%G $directory)" = "etcd:etcd" ]; then
    pass "$check_1_4_12"
  else
    warn "$check_1_4_12"
    owner=$(stat -c %U:%G $directory)
    warn "     * Wrong ownership for $directory:$owner"
  fi
else
  warn "$check_1_4_12"
  warn "     * Directory not found:$directory"
fi

check_1_4_13="1.4.13  - Ensure that the admin.conf file permissions are set to 644 or more restrictive (Scored)"
file="/etc/kubernetes/admin.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")

if [ -f $file ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_1_4_13"
  else
    warn "$check_1_4_13"
    perm=$(stat -c %a $file)
    warn "     * Wrong permissions for $file:$perm"
  fi
else
  warn "$check_1_4_13"
  warn "     * File not found:$file"
fi

check_1_4_14="1.4.14  - Ensure that the admin.conf file ownership is set to root:root (Scored)"
file="/etc/kubernetes/admin.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")

if [ -f $file ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_4_14"
  else
    warn "$check_1_4_14"
    owner=$(stat -c %U:%G $file)
    warn "     * Wrong ownership for $file:$owner"
  fi
else
  warn "$check_1_4_14"
  warn "     * File not found:$file"
fi

check_1_4_15="1.4.15  - Ensure that the scheduler.conf file permissions are set to 644 or more restrictive (Scored)"
file="/etc/kubernetes/scheduler.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")

if [ -f $file ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_1_4_15"
  else
    warn "$check_1_4_15"
    perm=$(stat -c %a $file)
    warn "     * Wrong permissions for $file:$perm"
  fi
else
  warn "$check_1_4_15"
  warn "     * File not found:$file"
fi

check_1_4_16="1.4.16  - Ensure that the scheduler.conf file ownership is set to root:root (Scored)"
file="/etc/kubernetes/scheduler.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")

if [ -f $file ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_4_16"
  else
    warn "$check_1_4_16"
    owner=$(stat -c %U:%G $file)
    warn "     * Wrong ownership for $file:$owner"
  fi
else
  warn "$check_1_4_16"
  warn "     * File not found:$file"
fi

check_1_4_17="1.4.17  - Ensure that the controller-manager.conf file permissions are set to 644 or more restrictive (Scored)"
file="/etc/kubernetes/controller-manager.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")

if [ -f $file ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_1_4_17"
  else
    warn "$check_1_4_17"
    perm=$(stat -c %a $file)
    warn "     * Wrong permissions for $file:$perm"
  fi
else
  warn "$check_1_4_17"
  warn "     * File not found:$file"
fi

check_1_4_18="1.4.18  - Ensure that the controller-manager.conf file ownership is set to root:root (Scored)"
file="/etc/kubernetes/controller-manager.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")

if [ -f $file ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_4_18"
  else
    warn "$check_1_4_18"
    owner=$(stat -c %U:%G $file)
    warn "     * Wrong ownership for $file:$owner"
  fi
else
  warn "$check_1_4_18"
  warn "     * File not found:$file"
fi

check_1_4_19="1.4.19  - Ensure that the Kubernetes PKI directory and file ownership is set to root:root (Scored)"
file="/etc/kubernetes/pki/"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
files=$(find $file)
pass=true
for f in ${files}; do
  if [ "$(stat -c %u%g $f)" != 00 ]; then
    pass=false;
    break;
  fi
done

if [ "$pass" = "true" ]; then
  pass "$check_1_4_19"
else
  warn "$check_1_4_19"
fi

check_1_4_20="1.4.20  - Ensure that the Kubernetes PKI certificate file permissions are set to 644 or more restrictive (Scored)"
files=$(find $file -name "*.crt")
pass=true
for f in ${files}; do
  if ! [ "$(stat -c %a $f)" -eq 644 -o "$(stat -c %a $f)" -eq 600 -o "$(stat -c %a $f)" -eq 400 ]; then
    pass=false;
    break;
  fi
done

if [ "$pass" = "true" ]; then
  pass "$check_1_4_20"
else
  warn "$check_1_4_20"
fi

check_1_4_21="1.4.21  - Ensure that the Kubernetes PKI key file permissions are set to 600 (Scored)"
files=$(find $file -name "*.key")
pass=true
for f in ${files}; do
  if ! [ "$(stat -c %a $f)" -eq 600 ]; then
    pass=false;
    break;
  fi
done

if [ "$pass" = "true" ]; then
  pass "$check_1_4_21"
else
  warn "$check_1_4_21"
fi

info "2.2 - Configuration Files"

check_2_2_1="2.2.1  - Ensure that the config file permissions are set to 644 or more restrictive"
if [ -f "/etc/kubernetes/config" ]; then
    file="/etc/kubernetes/config"
else
    file="/etc/kubernetes/kubelet.conf"
fi

if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_2_2_1"
  else
    warn "$check_2_2_1"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_2_2_1"
  info "     * File not found"
fi

check_2_2_2="2.2.2  - Ensure that the config file ownership is set to root:root"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_2_2_2"
  else
    warn "$check_2_2_2"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_2_2_2"
fi

check_2_2_3="2.2.3  - Ensure that the kubelet file permissions are set to 644 or more restrictive"
if [ -f "/etc/kubernetes/kubelet" ]; then
    file="/etc/kubernetes/kubelet"
else
    file="/etc/kubernetes/kubelet.conf"
fi

if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_2_2_3"
  else
    warn "$check_2_2_3"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_2_2_3"
  info "     * File not found"
fi

check_2_2_4="2.2.4  - Ensure that the kubelet file ownership is set to root:root"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_2_2_4"
  else
    warn "$check_2_2_4"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_2_2_4"
fi

check_2_2_5="2.2.5  - Ensure that the proxy file permissions are set to 644 or more restrictive"
file="/etc/kubernetes/proxy"

if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_2_2_5"
  else
    warn "$check_2_2_5"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_2_2_5"
  info "     * File not found"
fi

check_2_2_6="2.2.6  - Ensure that the proxy file ownership is set to root:root"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_2_2_6"
  else
    warn "$check_2_2_6"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_2_2_6"
fi



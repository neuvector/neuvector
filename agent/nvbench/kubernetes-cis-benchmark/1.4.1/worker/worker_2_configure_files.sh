info "2.2 - Configuration Files"

check_2_2_1="2.2.1  - Ensure that the kubelet service file permissions are set to 644 or more restrictive (Scored)"
file="/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"

if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_2_2_1"
  else
    warn "$check_2_2_1"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_2_2_1"
  info "     * File not found"
fi

check_2_2_2="2.2.2  - Ensure that the kubelet.conf file permissions are set to 644 or more restrictive (Scored)"
file="/etc/kubernetes/kubelet.conf"
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_2_2_2"
  else
    warn "$check_2_2_2"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_2_2_2"
  info "     * File not found"
fi


check_2_2_3="2.2.3  - Ensure that the kubelet.conf file ownership is set to root:root (Scored)"
file="/etc/kubernetes/kubelet.conf"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_2_2_3"
  else
    warn "$check_2_2_3"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_2_2_3"
fi

check_2_2_4="2.2.4  - Ensure that the kubelet service file ownership is set to root:root (Scored)"
file="/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"
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

check_2_2_5="2.2.5  - Ensure that the proxy kubeconfig file permissions are set to 644 or more restrictive (Scored)"
file=""
if check_argument "$CIS_PROXY_CMD" '--kubeconfig' >/dev/null 2>&1; then
  file=$(get_argument_value "$CIS_PROXY_CMD" '--kubeconfig'|cut -d " " -f 1)
fi

if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_2_2_5"
  else
    warn "$check_2_2_5"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_2_2_5"
  info "     * --kubeconfig not set"
fi

check_2_2_6="2.2.6  - Ensure that the proxy kubeconfig file ownership is set to root:root (Scored)"
file=""
if check_argument "$CIS_PROXY_CMD" '--kubeconfig' >/dev/null 2>&1; then
  file=$(get_argument_value "$CIS_PROXY_CMD" '--kubeconfig'|cut -d " " -f 1)
fi
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_2_2_6"
  else
    warn "$check_2_2_6"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_2_2_6"
  info "     * --kubeconfig not set"
fi

check_2_2_7="2.2.7  - Ensure that the certificate authorities file permissions are set to 644 or more restrictive (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--client-ca-file' >/dev/null 2>&1; then
  file=$(get_argument_value "$CIS_KUBELET_CMD" '--client-ca-file')
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_2_2_7"
    pass "       * client-ca-file: $file"
  else
    warn "$check_2_2_7"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_2_2_7"
  info "     * --client-ca-file not set"
fi

check_2_2_8="2.2.8  - Ensure that the client certificate authorities file ownership is set to root:root (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--client-ca-file' >/dev/null 2>&1; then
  file=$(get_argument_value "$CIS_KUBELET_CMD" '--client-ca-file')
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_2_2_8"
    pass "       * client-ca-file: $file"
  else
    warn "$check_2_2_8"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_2_2_8"
  info "     * --client-ca-file not set"
fi

check_2_2_9="2.2.9  - Ensure that the kubelet configuration file has permissions set to 644 or more restrictive (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--config' >/dev/null 2>&1; then
  file=$(get_argument_value "$CIS_KUBELET_CMD" '--config')
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_2_2_9"
    pass "       * config: $file"
  else
    warn "$check_2_2_9"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_2_2_9"
  info "     * --config not set"
fi

check_2_2_10="2.2.10  - Ensure that the kubelet configuration file ownership is set to root:root (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--config' >/dev/null 2>&1; then
  file=$(get_argument_value "$CIS_KUBELET_CMD" '--config')
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_2_2_10"
    pass "       * client: $file"
  else
    warn "$check_2_2_10"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_2_2_10"
  info "     * --config not set"
fi

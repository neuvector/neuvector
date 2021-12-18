info "4.1 - Worker Node Configuration Files"

check_4_1_1="4.1.1  - Ensure that the kubelet service file permissions are set to 644 or more restrictive (Scored)"
file="/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_4_1_1"
  else
    warn "$check_4_1_1"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_4_1_1"
  info "     * The kubelet service file not found"
fi

check_4_1_2="4.1.2  - Ensure that the kubelet service file ownership is set to root:root (Scored)"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_4_1_2"
  else
    warn "$check_4_1_2"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_4_1_2"
fi

check_4_1_3="4.1.3  - Ensure that the proxy kubeconfig file permissions are set to 644 or more restrictive (Scored)"
file=""
if check_argument "$CIS_PROXY_CMD" '--kubeconfig' >/dev/null 2>&1; then
    file=$(get_argument_value "$CIS_PROXY_CMD" '--kubeconfig'|cut -d " " -f 1)
fi

if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_4_1_3"
  else
    warn "$check_4_1_3"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_4_1_3"
  info "     * kubeconfig file not found"
fi

check_4_1_4="4.1.4  - Ensure that the proxy kubeconfig file ownership is set to root:root (Scored)"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_4_1_4"
  else
    warn "$check_4_1_4"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_4_1_4"
  info "     * kubeconfig file not found"
fi

check_4_1_5="4.1.5  - Ensure that the kubelet.conf file permissions are set to 644 or more restrictive (Scored)"
if [ -f "/var/lib/kube-proxy/kubeconfig" ]; then
    # kops
    file="/var/lib/kube-proxy/kubeconfig"
else
    file="/etc/kubernetes/proxy"
fi

if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_4_1_5"
  else
    warn "$check_4_1_5"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_4_1_5"
  info "     * File not found"
fi

check_4_1_6="4.1.6  - Ensure that the kubelet.conf file ownership is set to root:root (Scored)"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_4_1_6"
  else
    warn "$check_4_1_6"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_4_1_6"
fi

check_4_1_7="4.1.7  - Ensure that the certificate authorities file permissions are set to 644 or more restrictive (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--client-ca-file' >/dev/null 2>&1; then
  file=$(get_argument_value "$CIS_KUBELET_CMD" '--client-ca-file')
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_4_1_7"
    pass "       * client-ca-file: $file"
  else
    warn "$check_4_1_7"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_4_1_7"
  info "     * --client-ca-file not set"
fi

check_4_1_8="4.1.8  - Ensure that the client certificate authorities file ownership is set to root:root (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--client-ca-file' >/dev/null 2>&1; then
  file=$(get_argument_value "$CIS_KUBELET_CMD" '--client-ca-file')
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_4_1_8"
    pass "       * client-ca-file: $file"
  else
    warn "$check_4_1_8"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_4_1_8"
  info "     * --client-ca-file not set"
fi

check_4_1_9="4.1.9  - Ensure that the kubelet configuration file has permissions set to 644 or more restrictive (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--config' >/dev/null 2>&1; then
  file=$(get_argument_value "$CIS_KUBELET_CMD" '--config')
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_4_1_9"
    pass "       * kubelet configuration file: $file"
  else
    warn "$check_4_1_9"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_4_1_9"
  info "     * kubelet configuration file not set"
fi

check_4_1_10="4.1.10  - Ensure that the kubelet configuration file ownership is set to root:root (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--config' >/dev/null 2>&1; then
  file=$(get_argument_value "$CIS_KUBELET_CMD" '--config')
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_4_1_10"
    pass "       * kubelet configuration file: $file"
  else
    warn "$check_4_1_10"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_4_1_10"
  info "     * kubelet configuration file not set"
fi

info "4.2 - Kubelet"

#todo review all audits
check_4_2_1="4.2.1  - Ensure that the anonymous-auth argument is set to false (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--allow-privileged=false' >/dev/null 2>&1; then
    pass "$check_4_2_1"
else
    warn "$check_4_2_1"
fi

check_4_2_2="4.2.2  - Ensure that the --authorization-mode argument is not set to AlwaysAllow (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--authorization-mode=AlwaysAllow' >/dev/null 2>&1; then
    warn "$check_4_2_2"
else
    pass "$check_4_2_2"
fi

check_4_2_3="4.2.3  - Ensure that the --client-ca-file argument is set as appropriate (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--client-ca-file' >/dev/null 2>&1; then
    cafile=$(get_argument_value "$CIS_KUBELET_CMD" '--client-ca-file')
    pass "$check_4_2_3"
    pass "       * client-ca-file: $cafile"
else
    warn "$check_4_2_3"
fi

check_4_2_4="4.2.4  - Ensure that the --read-only-port argument is set to 0 (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--read-only-port' >/dev/null 2>&1; then
    port=$(get_argument_value "$CIS_KUBELET_CMD" '--read-only-port' | cut -d " " -f 1)
    if [ $port = "0" ]; then
        pass "$check_4_2_4"
    else
        warn "$check_4_2_4"
        warn "       * read-only-port: $port"
    fi
else
    warn "$check_4_2_4"
fi

check_4_2_5="4.2.5  - Ensure that the --streaming-connection-idle-timeout argument is not set to 0 (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--streaming-connection-idle-timeout=0' >/dev/null 2>&1; then
    timeout=$(get_argument_value "$CIS_KUBELET_CMD" '--streaming-connection-idle-timeout')
    warn "$check_4_2_5"
    warn "       * streaming-connection-idle-timeout: $timeout"
else
    pass "$check_4_2_5"
fi

check_4_2_6="4.2.6  - Ensure that the --protect-kernel-defaults argument is set to true (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--protect-kernel-defaults=true' >/dev/null 2>&1; then
    pass "$check_4_2_6"
else
    warn "$check_4_2_6"
fi

check_4_2_7="4.2.7  - Ensure that the --make-iptables-util-chains argument is set to true (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--make-iptables-util-chains=true' >/dev/null 2>&1; then
    pass "$check_4_2_7"
else
    warn "$check_4_2_7"
fi

check_4_2_8="4.2.8  - Ensure that the --hostname-override argument is not set (Not Scored)"
if check_argument "$CIS_KUBELET_CMD" '--hostname-override' >/dev/null 2>&1; then
    warn "$check_4_2_8"
else
    pass "$check_4_2_8"
fi

check_4_2_9="4.2.9  - Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture (Not Scored)"
if check_argument "$CIS_KUBELET_CMD" '--event-qps=0' >/dev/null 2>&1; then
    pass "$check_4_2_9"
else
    warn "$check_4_2_9"
fi

check_4_2_10="4.2.10  - Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--tls-cert-file' >/dev/null 2>&1; then
    if check_argument "$CIS_KUBELET_CMD" '--tls-private-key-file' >/dev/null 2>&1; then
        cfile=$(get_argument_value "$CIS_KUBELET_CMD" '--tls-cert-file')
        kfile=$(get_argument_value "$CIS_KUBELET_CMD" '--tls-private-key-file')
        pass "$check_4_2_10"
        pass "        * tls-cert-file: $cfile"
        pass "        * tls-private-key-file: $kfile"
    else
      warn "$check_4_2_10"
    fi
else
    warn "$check_4_2_10"
fi

check_4_2_11="4.2.11  - Ensure that the --rotate-certificates argument is not set to false (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--event-qps' >/dev/null 2>&1; then
    event=$(get_argument_value "$CIS_KUBELET_CMD" '--event-qps' | cut -d " " -f 1)
    if [ $event = "0" ]; then
        pass "$check_4_2_11"
    else
        warn "$check_4_2_11"
        warn "        * event-qps: $event"
    fi
else
    warn "$check_4_2_11"
fi

check_4_2_12="4.2.12  - Ensure that the RotateKubeletServerCertificate argument is set to true (Scored)"
file="/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"
found=$(sed -rn '/--feature-gates=RotateKubeletServerCertificate=true/p' $file)
if [ -z "$found" ]; then
    warn "$check_4_2_12"
else
    pass "$check_4_2_12"
fi

check_4_2_13="4.2.13  - Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers (Not Scored)"
if check_argument "$CIS_KUBELET_CMD" '--cadvisor-port' >/dev/null 2>&1; then
    port=$(get_argument_value "$CIS_KUBELET_CMD" '--cadvisor-port' | cut -d " " -f 1)
    if [ $port = "0" ]; then
        pass "$check_4_2_13"
    else
        warn "$check_4_2_13"
        warn "        * cadvisor-port: $port"
    fi
else
    warn "$check_4_2_13"
fi


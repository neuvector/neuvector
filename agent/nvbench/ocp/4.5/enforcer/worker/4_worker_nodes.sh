info "4.1 - Worker Node Configuration Files"

check_4_1_1="4.1.1  - Ensure that the kubelet service file permissions are set to 644 or more restrictive (Automated)"
file="/etc/systemd/system/kubelet.service"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
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

check_4_1_2="4.1.2  - Ensure that the kubelet service file ownership is set to root:root (Automated)"
file="/etc/systemd/system/kubelet.service"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
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

#todo review with Andson (/config/kube-proxy-config.yaml find / -name "kube-proxy-config.yaml")
check_4_1_3="4.1.3  - If proxy kubeconfig file exists ensure permissions are set to 644 or more restrictive (Manual)"
info "$check_4_1_3"

check_4_1_4="4.1.4  - If proxy kubeconfig file exists ensure ownership is set to root:root (Manual)"
info "$check_4_1_4"

check_4_1_5="4.1.5  - Ensure that the kubelet.conf file permissions are set to 644 or more restrictive (Manual)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
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

check_4_1_6="4.1.6  - Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root (Manual)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
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

check_4_1_7="4.1.7  - Ensure that the certificate authorities file permissions are set to 644 or more restrictive (Automated)"
file="/etc/kubernetes/kubelet-ca.crt"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_4_1_7"
  else
    warn "$check_4_1_7"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_4_1_7"
  info "     * File not found"
fi

check_4_1_8="4.1.8  - Ensure that the client certificate authorities file ownership is set to root:root (Automated)"
file="/etc/kubernetes/kubelet-ca.crt"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_4_1_8"
  else
    warn "$check_4_1_8"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_4_1_8"
fi

check_4_1_9="4.1.9  - Ensure that the kubelet --config configuration file has permissions set to 644 or more restrictive (Automated)"
file="/var/lib/kubelet/kubeconfig"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_4_1_9"
  else
    warn "$check_4_1_9"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_4_1_9"
  info "     * File not found"
fi

check_4_1_10="4.1.10  - Ensure that the kubelet configuration file ownership is set to root:root (Automated)"
file="/var/lib/kubelet/kubeconfig"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_4_1_10"
  else
    warn "$check_4_1_10"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_4_1_10"
fi

info "4.2 - Kubelet"

#todo review all audits
check_4_2_1="4.2.1  - Ensure that the anonymous-auth argument is set to false (Automated)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
ca_cert=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/kubelet-ca.crt")
output_ca=$(grep "clientCAFile: $ca_cert" $file)
output_auth=$(grep '\(enabled: false\)' $file)
if [ -z "$output_ca" ] || [ -z "$output_auth" ] ; then
    warn "$check_4_2_1"
else
    pass "$check_4_2_1"
fi

check_4_2_2="4.2.2  - Ensure that the --authorization-mode argument is not set to AlwaysAllow (Automated)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
output=$(grep '\(authorization-mode\)' $file)
if [ -z "$output" ]; then
    pass "$check_4_2_2"
else
    warn "$check_4_2_2"
fi

check_4_2_3="4.2.3  - Ensure that the --client-ca-file argument is set as appropriate (Automated)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
ca_cert=$(append_prefix "$CONFIG_PREFIX" "/etc/kubernetes/kubelet-ca.crt")
output_ca=$(grep "clientCAFile: $ca_cert" $file)
if [ -z "$output_ca" ]; then
    warn "$check_4_2_3"
else
    pass "$check_4_2_3"
fi

#todo review (ocp by default setting)
check_4_2_4="4.2.4  - Verify that the read only port is not used or is set to 0 (Automated)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
output=$(grep '\(read-only-port\)' $file)
if [ -z "$output" ]; then
    pass "$check_4_2_4"
else
    warn "$check_4_2_4"
fi

check_4_2_5="4.2.5  - Ensure that the --streaming-connection-idle-timeout argument is not set to 0 (Automated)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
output=$(grep '\(streaming-connection-idle-timeout\)' $file)
if [ -z "$output" ]; then
    pass "$check_4_2_5"
else
    warn "$check_4_2_5"
fi

check_4_2_6="4.2.6  - Ensure that the --protect-kernel-defaults argument is not set (Manual)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
output=$(grep '\(protectKernelDefaults\)' $file)
if [ -z "$output" ]; then
    pass "$check_4_2_5"
else
    warn "$check_4_2_5"
fi

check_4_2_7="4.2.7  - Ensure that the --make-iptables-util-chains argument is set to true (Manual)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
output=$(grep '\(make-iptables-util-chains\)' $file)
if [ -z "$output" ]; then
    pass "$check_4_2_7"
else
    warn "$check_4_2_7"
fi

check_4_2_8="4.2.8  - Ensure that the --hostname-override argument is not set (Manual)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
output=$(grep '\(hostname-override\)' $file)
if [ -z "$output" ]; then
    pass "$check_4_2_7"
else
    warn "$check_4_2_7"
fi

check_4_2_9="4.2.9  - Ensure that the kubeAPIQPS [--event-qps] argument is set to 0 or a level which ensures appropriate event capture (Automated)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
output=$(grep '\(kubeAPIQPS: 50\)' $file)
if [ -z "$output" ]; then
    warn "$check_4_2_9"
else
    pass "$check_4_2_9"
fi

check_4_2_10="4.2.10  - Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Automated)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
output_cert=$(grep '\(tls-cert-file\)' $file)
output_key=$(grep '\(tls-private-key-file\)' $file)
if [ -z "$output_cert" ] && [ -z "$output_key" ]; then
    pass "$check_4_2_10"
else
    warn "$check_4_2_10"
fi
#if check_argument "$CIS_KUBELET_CMD" '--tls-cert-file' >/dev/null 2>&1; then
#    if check_argument "$CIS_KUBELET_CMD" '--tls-private-key-file' >/dev/null 2>&1; then
#        cfile=$(get_argument_value "$CIS_KUBELET_CMD" '--tls-cert-file')
#        kfile=$(get_argument_value "$CIS_KUBELET_CMD" '--tls-private-key-file')
#        pass "$check_4_2_10"
#        pass "        * tls-cert-file: $cfile"
#        pass "        * tls-private-key-file: $kfile"
#    else
#      warn "$check_4_2_10"
#    fi
#else
#    warn "$check_4_2_10"
#fi

check_4_2_11="4.2.11  - Ensure that the --rotate-certificates argument is not set to false (Manual)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
output1=$(grep '\(rotateKubeletClientCertificates: false\)' $file)
output2=$(grep '\(rotateCertificates: true\)' $file)
if [ -z "$output1"] && [ -n "$output2" ]; then
    pass "$check_4_2_11"
else
    warn "$check_4_2_11"
fi
#if check_argument "$CIS_KUBELET_CMD" '--event-qps' >/dev/null 2>&1; then
#    event=$(get_argument_value "$CIS_KUBELET_CMD" '--event-qps' | cut -d " " -f 1)
#    if [ $event = "0" ]; then
#        pass "$check_4_2_11"
#    else
#        warn "$check_4_2_11"
#        warn "        * event-qps: $event"
#    fi
#else
#    warn "$check_4_2_11"
#fi

check_4_2_12="4.2.12  - Verify that the RotateKubeletServerCertificate argument is set to true (Manual)"
file="/etc/kubernetes/kubelet.conf"
file=$(append_prefix "$CONFIG_PREFIX" "$file")
output1=$(grep '\(RotateKubeletServerCertificate: true\)' $file)
output2=$(grep '\(rotateCertificates: true\)' $file)
if [ -n "$output1" ] && [ -n "$output2" ] ; then
    pass "$check_4_2_12"
else
    warn "$check_4_2_12"
fi

check_4_2_13="4.2.13  - Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers (Manual)"
info "$check_4_2_13"
info "TLS ciphers have had a number of known vulnerabilities and weaknesses, which can reduce the protection provided by them. By default Kubernetes supports a number of TLS ciphersuites including some that have security concerns, weakening the protection provided."

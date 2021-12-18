info "2.1 - Kubelet"

check_2_1_1="2.1.1  - Ensure that the --anonymous-auth argument is set to false (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--anonymous-auth=false' >/dev/null 2>&1; then
    pass "$check_2_1_1"
else
    warn "$check_2_1_1"
fi

check_2_1_2="2.1.2  - Ensure that the --authorization-mode argument is not set to AlwaysAllow (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--authorization-mode=AlwaysAllow' >/dev/null 2>&1; then
    warn "$check_2_1_2"
else
    pass "$check_2_1_2"
fi

check_2_1_3="2.1.3  - Ensure that the --client-ca-file argument is set as appropriate (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--client-ca-file' >/dev/null 2>&1; then
    cafile=$(get_argument_value "$CIS_KUBELET_CMD" '--client-ca-file')
    pass "$check_2_1_3"
    pass "       * client-ca-file: $cafile"
else
    warn "$check_2_1_3"
fi

check_2_1_4="2.1.4  - Ensure that the --read-only-port argument is set to 0 (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--read-only-port' >/dev/null 2>&1; then
    port=$(get_argument_value "$CIS_KUBELET_CMD" '--read-only-port' | cut -d " " -f 1)
    if [ $port = "0" ]; then
        pass "$check_2_1_4"
    else
        warn "$check_2_1_4"
        warn "       * read-only-port: $port"
    fi
else
    warn "$check_2_1_4"
fi

check_2_1_5="2.1.5  - Ensure that the --streaming-connection-idle-timeout argument is not set to 0 (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--streaming-connection-idle-timeout=0' >/dev/null 2>&1; then
    timeout=$(get_argument_value "$CIS_KUBELET_CMD" '--streaming-connection-idle-timeout')
    warn "$check_2_1_5"
    warn "       * streaming-connection-idle-timeout: $timeout"
else
    pass "$check_2_1_5"
fi

check_2_1_6="2.1.6  - Ensure that the --protect-kernel-defaults argument is set to true (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--protect-kernel-defaults=true' >/dev/null 2>&1; then
    pass "$check_2_1_6"
else
    warn "$check_2_1_6"
fi

check_2_1_7="2.1.7  - Ensure that the --make-iptables-util-chains argument is set to true (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--make-iptables-util-chains=true' >/dev/null 2>&1; then
    pass "$check_2_1_7"
else
    warn "$check_2_1_7"
fi

check_2_1_8="2.1.8  - Ensure that the --hostname-override argument is not set (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--hostname-override' >/dev/null 2>&1; then
    warn "$check_2_1_8"
else
    pass "$check_2_1_8"
fi

check_2_1_9="2.1.9  - Ensure that the --event-qps argument is set to 0 (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--event-qps' >/dev/null 2>&1; then
    event=$(get_argument_value "$CIS_KUBELET_CMD" '--event-qps' | cut -d " " -f 1)
    if [ $event = "0" ]; then
        pass "$check_2_1_9"
    else
        warn "$check_2_1_9"
        warn "        * event-qps: $event"
    fi
else
    warn "$check_2_1_9"
fi

check_2_1_10="2.1.10  - Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--tls-cert-file' >/dev/null 2>&1; then
    if check_argument "$CIS_KUBELET_CMD" '--tls-private-key-file' >/dev/null 2>&1; then
        cfile=$(get_argument_value "$CIS_KUBELET_CMD" '--tls-cert-file')
        kfile=$(get_argument_value "$CIS_KUBELET_CMD" '--tls-private-key-file')
        pass "$check_2_1_10"
        pass "        * tls-cert-file: $cfile"
        pass "        * tls-private-key-file: $kfile"
    else
      warn "$check_2_1_10"
    fi
else
    warn "$check_2_1_10"
fi

check_2_1_11="2.1.11  - [DEPRECATED] Ensure that the --cadvisor-port argument is set to 0 (Not Scored)"
pass "$check_2_1_11"

check_2_1_12="2.1.12  - Ensure that the --rotate-certificates argument is not set to false (Scored)"
if check_argument "$CIS_KUBELET_CMD" '--rotate-certificates=true' >/dev/null 2>&1; then
    pass "$check_2_1_12"
else
    warn "$check_2_1_12"
fi

check_2_1_13="2.1.13  - Ensure that the RotateKubeletServerCertificate argument is set to true (Scored)"
file="/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"
found=$(sed -rn '/--feature-gates=RotateKubeletServerCertificate=true/p' $file)
if [ -z "$found" ]; then
    warn "$check_2_1_13"
else
    pass "$check_2_1_13"
fi

check_2_1_14="2.1.14  - Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers (Not Scored)"
if check_argument "$CIS_KUBELET_CMD" '--tls-cipher-suites' >/dev/null 2>&1; then
    ciphers=$(get_argument_value "$CIS_APISERVER_CMD" '--tls-cipher-suites'|cut -d " " -f 1)
    found=$(echo $ciphers| sed -rn '/(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305|TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305|TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384|TLS_RSA_WITH_AES_256_GCM_SHA384|TLS_RSA_WITH_AES_128_GCM_SHA256)/p')
    if [ ! -z "$found" ]; then
      pass "$check_2_1_14"
    else
      warn "$check_2_1_14"
    fi
else
    warn "$check_2_1_14"
fi

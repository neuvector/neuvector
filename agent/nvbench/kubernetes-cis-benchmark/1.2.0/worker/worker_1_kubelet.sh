info "2.1 - Kubelet"

check_2_1_1="2.1.1  - Ensure that the --allow-privileged argument is set to false"
if check_argument "$CIS_KUBELET_CMD" '--allow-privileged=false' >/dev/null 2>&1; then
    pass "$check_2_1_1"
else
    warn "$check_2_1_1"
fi

check_2_1_2="2.1.2  - Ensure that the --anonymous-auth argument is set to false"
if check_argument "$CIS_KUBELET_CMD" '--anonymous-auth=false' >/dev/null 2>&1; then
    pass "$check_2_1_2"
else
    warn "$check_2_1_2"
fi

check_2_1_3="2.1.3  - Ensure that the --authorization-mode argument is not set to AlwaysAllow"
if check_argument "$CIS_KUBELET_CMD" '--authorization-mode=AlwaysAllow' >/dev/null 2>&1; then
    warn "$check_2_1_3"
else
    pass "$check_2_1_3"
fi

check_2_1_4="2.1.4  - Ensure that the --client-ca-file argument is set as appropriate"
if check_argument "$CIS_KUBELET_CMD" '--client-ca-file' >/dev/null 2>&1; then
    cafile=$(get_argument_value "$CIS_KUBELET_CMD" '--client-ca-file')
    pass "$check_2_1_4"
    pass "       * client-ca-file: $cafile"
else
    warn "$check_2_1_4"
fi

check_2_1_5="2.1.5  - Ensure that the --read-only-port argument is set to 0"
if check_argument "$CIS_KUBELET_CMD" '--read-only-port' >/dev/null 2>&1; then
    port=$(get_argument_value "$CIS_KUBELET_CMD" '--read-only-port' | cut -d " " -f 1)
    if [ $port = "0" ]; then
        pass "$check_2_1_5"
    else
        warn "$check_2_1_5"
        warn "       * read-only-port: $port"
    fi
else
    warn "$check_2_1_5"
fi

check_2_1_6="2.1.6  - Ensure that the --streaming-connection-idle-timeout argument is not set to 0"
if check_argument "$CIS_KUBELET_CMD" '--streaming-connection-idle-timeout=0' >/dev/null 2>&1; then
    timeout=$(get_argument_value "$CIS_KUBELET_CMD" '--streaming-connection-idle-timeout')
    warn "$check_2_1_6"
    warn "       * streaming-connection-idle-timeout: $timeout"
else
    pass "$check_2_1_6"
fi

check_2_1_7="2.1.7  - Ensure that the --protect-kernel-defaults argument is set to true"
if check_argument "$CIS_KUBELET_CMD" '--protect-kernel-defaults=true' >/dev/null 2>&1; then
    pass "$check_2_1_7"
else
    warn "$check_2_1_7"
fi

check_2_1_8="2.1.8  - Ensure that the --make-iptables-util-chains argument is set to true"
if check_argument "$CIS_KUBELET_CMD" '--make-iptables-util-chains=true' >/dev/null 2>&1; then
    pass "$check_2_1_8"
else
    warn "$check_2_1_8"
fi

check_2_1_9="2.1.9  - Ensure that the --keep-terminated-pod-volumes argument is set to false"
if check_argument "$CIS_KUBELET_CMD" '--keep-terminated-pod-volumes=false' >/dev/null 2>&1; then
    pass "$check_2_1_9"
else
    warn "$check_2_1_9"
fi

check_2_1_10="2.1.10  - Ensure that the --hostname-override argument is not set"
if check_argument "$CIS_KUBELET_CMD" '--hostname-override' >/dev/null 2>&1; then
    warn "$check_2_1_10"
else
    pass "$check_2_1_10"
fi

check_2_1_11="2.1.11  - Ensure that the --event-qps argument is set to 0"
if check_argument "$CIS_KUBELET_CMD" '--event-qps' >/dev/null 2>&1; then
    event=$(get_argument_value "$CIS_KUBELET_CMD" '--event-qps' | cut -d " " -f 1)
    if [ $event = "0" ]; then
        pass "$check_2_1_11"
    else
        warn "$check_2_1_11"
        warn "        * event-qps: $event"
    fi
else
    warn "$check_2_1_11"
fi

check_2_1_12="2.1.12  - Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate"
if check_argument "$CIS_KUBELET_CMD" '--tls-cert-file' >/dev/null 2>&1; then
    if check_argument "$CIS_KUBELET_CMD" '--tls-private-key-file' >/dev/null 2>&1; then
        cfile=$(get_argument_value "$CIS_KUBELET_CMD" '--tls-cert-file')
        kfile=$(get_argument_value "$CIS_KUBELET_CMD" '--tls-private-key-file')
        pass "$check_2_1_12"
        pass "        * tls-cert-file: $cfile"
        pass "        * tls-private-key-file: $kfile"
    else
      warn "$check_2_1_12"
    fi
else
    warn "$check_2_1_12"
fi

check_2_1_13="2.1.13  - Ensure that the --cadvisor-port argument is set to 0"
if check_argument "$CIS_KUBELET_CMD" '--cadvisor-port' >/dev/null 2>&1; then
    port=$(get_argument_value "$CIS_KUBELET_CMD" '--cadvisor-port' | cut -d " " -f 1)
    if [ $port = "0" ]; then
        pass "$check_2_1_13"
    else
        warn "$check_2_1_13"
        warn "        * cadvisor-port: $port"
    fi
else
    warn "$check_2_1_13"
fi


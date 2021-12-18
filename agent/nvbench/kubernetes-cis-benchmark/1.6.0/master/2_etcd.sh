info "2 - etcd"

check_2_1="2.1  - Ensure that the --cert-file and --key-file arguments are set as appropriate (Automated)"
if check_argument "$CIS_ETCD_CMD" '--cert-file' >/dev/null 2>&1; then
    if check_argument "$CIS_ETCD_CMD" '--key-file' >/dev/null 2>&1; then
        cfile=$(get_argument_value "$CIS_ETCD_CMD" '--cert-file')
        kfile=$(get_argument_value "$CIS_ETCD_CMD" '--key-file')
        pass "$check_2_1"
        pass "       * cert-file: $cfile"
        pass "       * key-file: $kfile"
    else
      warn "$check_2_1"
    fi
else
    warn "$check_2_1"
fi

check_2_2="2.2  - Ensure that the --client-cert-auth argument is set to true (Automated)"
if check_argument "$CIS_ETCD_CMD" '--client-cert-auth' >/dev/null 2>&1; then
    pass "$check_2_2"
else
    warn "$check_2_2"
fi

check_2_3="2.3  - Ensure that the --auto-tls argument is not set to true (Automated)"
if check_argument "$CIS_ETCD_CMD" '--auto-tls=true' >/dev/null 2>&1; then
    warn "$check_2_3"
else
    pass "$check_2_3"
fi

check_2_4="2.4  - Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate (Automated)"
if check_argument "$CIS_ETCD_CMD" '--peer-cert-file' >/dev/null 2>&1; then
    if check_argument "$CIS_ETCD_CMD" '--peer-key-file' >/dev/null 2>&1; then
        cfile=$(get_argument_value "$CIS_ETCD_CMD" '--peer-cert-file')
        kfile=$(get_argument_value "$CIS_ETCD_CMD" '--peer-key-file')
        pass "$check_2_4"
        pass "       * peer-cert-file: $cfile"
        pass "       * peer-key-file: $kfile"
    else
          warn "$check_2_4"
    fi
else
    warn "$check_2_4"
fi

check_2_5="2.5  - Ensure that the --peer-client-cert-auth argument is set to true (Automated)"
if check_argument "$CIS_ETCD_CMD" '--peer-client-cert-auth=true' >/dev/null 2>&1; then
    pass "$check_2_5"
else
    warn "$check_2_5"
fi

check_2_6="2.6  - Ensure that the --peer-auto-tls argument is not set to true (Automated)"
if check_argument "$CIS_ETCD_CMD" '--peer-auto-tls=true' >/dev/null 2>&1; then
    warn "$check_2_6"
else
    pass "$check_2_6"
fi

#todo apiserver vs kube-apiserver
check_2_7="2.7  - Ensure that a unique Certificate Authority is used for etcd (Manual)"
if check_argument "$CIS_ETCD_CMD" '--trusted-ca-file' >/dev/null 2>&1; then
    if check_argument "$CIS_APISERVER_CMD" '--client-ca-file' >/dev/null 2>&1; then
        tfile=$(get_argument_value "$CIS_ETCD_CMD" '--trusted-ca-file')
        cfile=$(get_argument_value "$CIS_APISERVER_CMD" '--client-ca-file')
        if [ "$tfile" = "$cfile" ]; then
            pass "$check_2_7"
            pass "       * trusted-ca-file: $tfile"
            pass "       * client-ca-file: $cfile"
        else
          warn "$check_2_7"
        fi
    else
        warn "$check_2_7"
        warn "       * client-ca-file doesn't exist"
    fi
else
    warn "$check_2_7"
    warn "       * trusted-ca-file doesn't exist"
fi

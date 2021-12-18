info "1.5 - etcd"

check_1_5_1="1.5.1  - Ensure that the --cert-file and --key-file arguments are set as appropriate (Scored)"
if check_argument "$CIS_ETCD_CMD" '--cert-file' >/dev/null 2>&1; then
    if check_argument "$CIS_ETCD_CMD" '--key-file' >/dev/null 2>&1; then
        cfile=$(get_argument_value "$CIS_ETCD_CMD" '--cert-file')
        kfile=$(get_argument_value "$CIS_ETCD_CMD" '--key-file')
        pass "$check_1_5_1"
        pass "       * cert-file: $cfile"
        pass "       * key-file: $kfile"
    else
      warn "$check_1_5_1"
    fi
else
    warn "$check_1_5_1"
fi

check_1_5_2="1.5.2  - Ensure that the --client-cert-auth argument is set to true (Scored)"
if check_argument "$CIS_ETCD_CMD" '--client-cert-auth' >/dev/null 2>&1; then
    pass "$check_1_5_2"
else
    warn "$check_1_5_2"
fi

check_1_5_3="1.5.3  - Ensure that the --auto-tls argument is not set to true (Scored)"
if check_argument "$CIS_ETCD_CMD" '--auto-tls=true' >/dev/null 2>&1; then
    warn "$check_1_5_3"
else
    pass "$check_1_5_3"
fi

check_1_5_4="1.5.4  - Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate (Scored)"
if check_argument "$CIS_ETCD_CMD" '--peer-cert-file' >/dev/null 2>&1; then
    if check_argument "$CIS_ETCD_CMD" '--peer-key-file' >/dev/null 2>&1; then
        cfile=$(get_argument_value "$CIS_ETCD_CMD" '--peer-cert-file')
        kfile=$(get_argument_value "$CIS_ETCD_CMD" '--peer-key-file')
        pass "$check_1_5_4"
        pass "       * peer-cert-file: $cfile"
        pass "       * peer-key-file: $kfile"
    else
          warn "$check_1_5_4"
    fi
else
    warn "$check_1_5_4"
fi

check_1_5_5="1.5.5  - Ensure that the --peer-client-cert-auth argument is set to true (Scored)"
if check_argument "$CIS_ETCD_CMD" '--peer-client-cert-auth' >/dev/null 2>&1; then
    pass "$check_1_5_5"
else
    warn "$check_1_5_5"
fi

check_1_5_6="1.5.6  - Ensure that the --peer-auto-tls argument is not set to true (Scored)"
if check_argument "$CIS_ETCD_CMD" '--peer-auto-tls=true' >/dev/null 2>&1; then
    warn "$check_1_5_6"
else
    pass "$check_1_5_6"
fi

check_1_5_7="1.5.7  - Ensure that a unique Certificate Authority is used for etcd (Not Scored)"
if check_argument "$CIS_ETCD_CMD" '--trusted-ca-file' >/dev/null 2>&1; then
    if check_argument "$CIS_APISERVER_CMD" '--client-ca-file' >/dev/null 2>&1; then
        tfile=$(get_argument_value "$CIS_ETCD_CMD" '--trusted-ca-file')
        cfile=$(get_argument_value "$CIS_APISERVER_CMD" '--client-ca-file')
        if [ "$tfile" = "$cfile" ]; then
            pass "$check_1_5_7"
            pass "       * trusted-ca-file: $tfile"
            pass "       * client-ca-file: $cfile"
        else
          warn "$check_1_5_7"
        fi
    else
        warn "$check_1_5_7"
        warn "       * client-ca-file doesn't exist"
    fi
else
    warn "$check_1_5_7"
    warn "       * trusted-ca-file doesn't exist"
fi

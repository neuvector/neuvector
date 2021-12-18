info "1.3 - Controller Manager"

check_1_3_1="1.3.1  - Ensure that the --terminated-pod-gc-threshold argument is set as appropriate (Scored)"
# Filter out processes like "/bin/tee -a /var/log/kube-controller-manager.log"
# which exist on kops-managed clusters.
if check_argument "$CIS_MANAGER_CMD" '--terminated-pod-gc-threshold' >/dev/null 2>&1; then
    threshold=$(get_argument_value "$CIS_MANAGER_CMD" '--terminated-pod-gc-threshold')
    pass "$check_1_3_1"
    pass "       * terminated-pod-gc-threshold: $threshold"
else
    warn "$check_1_3_1"
fi

check_1_3_2="1.3.2  - Ensure that the --profiling argument is set to false (Scored)"
if check_argument "$CIS_MANAGER_CMD" '--profiling=false' >/dev/null 2>&1; then
    pass "$check_1_3_2"
else
    warn "$check_1_3_2"
fi

check_1_3_3="1.3.3  - Ensure that the --use-service-account-credentials argument is set to true (Scored)"
if check_argument "$CIS_MANAGER_CMD" '--use-service-account-credentials' >/dev/null 2>&1; then
    pass "$check_1_3_3"
else
    warn "$check_1_3_3"
fi

check_1_3_4="1.3.4  - Ensure that the --service-account-private-key-file argument is set as appropriate (Scored)"
if check_argument "$CIS_MANAGER_CMD" '--service-account-private-key-file' >/dev/null 2>&1; then
    keyfile=$(get_argument_value "$CIS_MANAGER_CMD" '--service-account-private-key-file')
    pass "$check_1_3_4"
    pass "       * service-account-private-key-file: $keyfile"
else
    warn "$check_1_3_4"
fi

check_1_3_5="1.3.5  - Ensure that the --root-ca-file argument is set as appropriate (Scored)"
if check_argument "$CIS_MANAGER_CMD" '--root-ca-file' >/dev/null 2>&1; then
    cafile=$(get_argument_value "$CIS_MANAGER_CMD" '--root-ca-file')
    pass "$check_1_3_5"
    pass "       * root-ca-file: $cafile"
else
    warn "$check_1_3_5"
fi

check_1_3_6="1.3.6  - Ensure that the RotateKubeletServerCertificate argument is set to true (Scored)"
if check_argument "$CIS_MANAGER_CMD" '--feature-gates' >/dev/null 2>&1; then
    serverCert=$(get_argument_value "$CIS_MANAGER_CMD" '--feature-gates')
    found=$(echo $serverCert| grep 'RotateKubeletServerCertificate=true')
    if [ ! -z $found ]; then
      pass "$check_1_3_6"
    else
      warn "$check_1_3_6"
    fi
else
    warn "$check_1_3_6"
fi

check_1_3_7="1.3.7  - Ensure that the --address argument is set to 127.0.0.1 (Scored)"
if get_argument_value "$CIS_MANAGER_CMD" '--address'| grep '127.0.0.1' >/dev/null 2>&1; then
    pass "$check_1_3_7"
else
    warn "$check_1_3_7"
fi

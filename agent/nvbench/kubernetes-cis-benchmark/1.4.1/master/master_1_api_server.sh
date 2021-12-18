info "1.1 - API Server"

check_1_1_1="1.1.1  - Ensure that the --anonymous-auth argument is set to false (Not Scored)"
if check_argument "$CIS_APISERVER_CMD" '--anonymous-auth=false' >/dev/null 2>&1; then
    pass "$check_1_1_1"
else
    warn "$check_1_1_1"
fi

check_1_1_2="1.1.2  - Ensure that the --basic-auth-file argument is not set (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--basic-auth-file' >/dev/null 2>&1; then
    warn "$check_1_1_2"
else
    pass "$check_1_1_2"
fi

check_1_1_3="1.1.3  - Ensure that the --insecure-allow-any-token argument is not set (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--insecure-allow-any-token' >/dev/null 2>&1; then
    warn "$check_1_1_3"
else
    pass "$check_1_1_3"
fi

check_1_1_4="1.1.4  - Ensure that the --kubelet-https argument is set to true (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--kubelet-https=false' >/dev/null 2>&1; then
    warn "$check_1_1_4"
else
    pass "$check_1_1_4"
fi

check_1_1_5="1.1.5  - Ensure that the --insecure-bind-address argument is not set (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--insecure-bind-address' >/dev/null 2>&1; then
    address=$(get_argument_value "$CIS_APISERVER_CMD" '--insecure-bind-address'|cut -d " " -f 1)
    if [ "$address" = "127.0.0.1" ]; then
        pass "$check_1_1_5"
        pass "       * insecure-bind-address: $address"
    else
        warn "$check_1_1_5"
        warn "       * insecure-bind-address: $address"
    fi
else
    pass "$check_1_1_5"
fi

check_1_1_6="1.1.6  - Ensure that the --insecure-port argument is set to 0 (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--insecure-port' >/dev/null 2>&1; then
    port=$(get_argument_value "$CIS_APISERVER_CMD" '--insecure-port'|cut -d " " -f 1)
    if [ "$port" = "0" ]; then
        pass "$check_1_1_6"
    else
        warn "$check_1_1_6"
        warn "       * insecure-port: $port"
    fi
else
    warn "$check_1_1_6"
fi

check_1_1_7="1.1.7  - Ensure that the --secure-port argument is not set to 0 (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--secure-port' >/dev/null 2>&1; then
    port=$(get_argument_value "$CIS_APISERVER_CMD" '--secure-port'|cut -d " " -f 1)
    if [ "$port" = "0" ]; then
        warn "$check_1_1_7"
        warn "       * secure-port: $port"
    else
        pass "$check_1_1_7"
    fi
else
    pass "$check_1_1_7"
fi

check_1_1_8="1.1.8  - Ensure that the --profiling argument is set to false (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--profiling=false' >/dev/null 2>&1; then
    pass "$check_1_1_8"
else
    warn "$check_1_1_8"
fi

check_1_1_9="1.1.9  - Ensure that the --repair-malformed-updates argument is set to false (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--repair-malformed-updates=false' >/dev/null 2>&1; then
    pass "$check_1_1_9"
else
    warn "$check_1_1_9"
fi

check_1_1_10="1.1.10  - Ensure that the admission control plugin AlwaysAdmit is not set (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'AlwaysAdmit' >/dev/null 2>&1; then
    warn "$check_1_1_10"
else
    pass "$check_1_1_10"
fi

check_1_1_11="1.1.11  - Ensure that the admission control plugin AlwaysPullImages is set (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'AlwaysPullImages' >/dev/null 2>&1; then
    pass "$check_1_1_11"
else
    warn "$check_1_1_11"
fi

check_1_1_12="1.1.12  - [DEPRECATED] Ensure that the admission control plugin DenyEscalatingExec is set (Not Scored)"
pass "$check_1_1_12"

check_1_1_13="1.1.13  - Ensure that the admission control plugin SecurityContextDeny is set (Not Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'SecurityContextDeny' >/dev/null 2>&1; then
    pass "$check_1_1_13"
else
    warn "$check_1_1_13"
fi

check_1_1_14="1.1.14  - Ensure that the admission control plugin NamespaceLifecycle is set (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--disable-admission-plugins'| grep 'NamespaceLifecycle' >/dev/null 2>&1; then
    warn "$check_1_1_14"
else
    pass "$check_1_1_14"
fi

check_1_1_15="1.1.15  - Ensure that the --audit-log-path argument is set as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--audit-log-path' >/dev/null 2>&1; then
    pass "$check_1_1_15"
else
    warn "$check_1_1_15"
fi

check_1_1_16="1.1.16  - Ensure that the --audit-log-maxage argument is set to 30 or as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--audit-log-maxage' >/dev/null 2>&1; then
    maxage=$(get_argument_value "$CIS_APISERVER_CMD" '--audit-log-maxage'|cut -d " " -f 1)
    if [ "$maxage" = "30" ]; then
        pass "$check_1_1_16"
        pass "        * audit-log-maxage: $maxage"
    else
        warn "$check_1_1_16"
        warn "        * audit-log-maxage: $maxage"
    fi
else
    warn "$check_1_1_16"
fi

check_1_1_17="1.1.17  - Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--audit-log-maxbackup' >/dev/null 2>&1; then
    maxbackup=$(get_argument_value "$CIS_APISERVER_CMD" '--audit-log-maxbackup'|cut -d " " -f 1)
    if [ "$maxbackup" = "10" ]; then
        pass "$check_1_1_17"
        pass "        * audit-log-maxbackup: $maxbackup"
    else
        warn "$check_1_1_17"
        warn "        * audit-log-maxbackup: $maxbackup"
    fi
else
    warn "$check_1_1_17"
fi

check_1_1_18="1.1.18  - Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--audit-log-maxsize' >/dev/null 2>&1; then
    maxsize=$(get_argument_value "$CIS_APISERVER_CMD" '--audit-log-maxsize'|cut -d " " -f 1)
    if [ "$maxsize" = "100" ]; then
        pass "$check_1_1_18"
        pass "        * audit-log-maxsize: $maxsize"
    else
        warn "$check_1_1_18"
        warn "        * audit-log-maxsize: $maxsize"
    fi
else
    warn "$check_1_1_18"
fi

check_1_1_19="1.1.19  - Ensure that the --authorization-mode argument is not set to AlwaysAllow (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--authorization-mode'| grep 'AlwaysAllow' >/dev/null 2>&1; then
    warn "$check_1_1_19"
else
    pass "$check_1_1_19"
fi

check_1_1_20="1.1.20  - Ensure that the --token-auth-file parameter is not set (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--token-auth-file' >/dev/null 2>&1; then
    warn "$check_1_1_20"
else
    pass "$check_1_1_20"
fi

check_1_1_21="1.1.21  - Ensure that the --kubelet-certificate-authority argument is set as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--kubelet-certificate-authority' >/dev/null 2>&1; then
    pass "$check_1_1_21"
else
    warn "$check_1_1_21"
fi

check_1_1_22="1.1.22  - Ensure that the --kubelet-client-certificate and --kubelet-client- key arguments are set as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--kubelet-client-certificate' >/dev/null 2>&1; then
    if check_argument "$CIS_APISERVER_CMD" '--kubelet-client-key' >/dev/null 2>&1; then
        certificate=$(get_argument_value "$CIS_APISERVER_CMD" '--kubelet-client-certificate')
        key=$(get_argument_value "$CIS_APISERVER_CMD" '--kubelet-client-key')
        pass "$check_1_1_22"
        pass "       * kubelet-client-certificate: $certificate"
        pass "       * kubelet-client-key: $key"
    else
        warn "$check_1_1_22"
    fi
else
    warn "$check_1_1_22"
fi

check_1_1_23="1.1.23  - Ensure that the --service-account-lookup argument is set to true (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--service-account-lookup' >/dev/null 2>&1; then
    pass "$check_1_1_23"
else
    warn "$check_1_1_23"
fi

check_1_1_24="1.1.24  - Ensure that the admission control plugin PodSecurityPolicy is set (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'PodSecurityPolicy' >/dev/null 2>&1; then
    pass "$check_1_1_24"
else
    warn "$check_1_1_24"
fi

check_1_1_25="1.1.25  - Ensure that the --service-account-key-file argument is set as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--service-account-key-file' >/dev/null 2>&1; then
    file=$(get_argument_value "$CIS_APISERVER_CMD" '--service-account-key-file')
    pass "$check_1_1_25"
    pass "        * service-account-key-file: $file"
else
    warn "$check_1_1_25"
fi

check_1_1_26="1.1.26  - Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--etcd-certfile' >/dev/null 2>&1; then
    if check_argument "$CIS_APISERVER_CMD" '--etcd-keyfile' >/dev/null 2>&1; then
        certfile=$(get_argument_value "$CIS_APISERVER_CMD" '--etcd-certfile')
        keyfile=$(get_argument_value "$CIS_APISERVER_CMD" '--etcd-keyfile')
        pass "$check_1_1_26"
        pass "        * etcd-certfile: $certfile"
        pass "        * etcd-keyfile: $keyfile"
    else
        warn "$check_1_1_26"
    fi
else
    warn "$check_1_1_26"
fi

check_1_1_27="1.1.27  - Ensure that the admission control plugin ServiceAccount is set (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--disable-admission-plugins'| grep 'ServiceAccount' >/dev/null 2>&1; then
    warn "$check_1_1_27"
else
    pass "$check_1_1_27"
fi

check_1_1_28="1.1.28  - Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--tls-cert-file' >/dev/null 2>&1; then
    if check_argument "$CIS_APISERVER_CMD" '--tls-private-key-file' >/dev/null 2>&1; then
        certfile=$(get_argument_value "$CIS_APISERVER_CMD" '--tls-cert-file')
        keyfile=$(get_argument_value "$CIS_APISERVER_CMD" '--tls-private-key-file')
        pass "$check_1_1_28"
        pass "        * tls-cert-file: $certfile"
        pass "        * tls-private-key-file: $keyfile"
    else
        warn "$check_1_1_28"
    fi
else
    warn "$check_1_1_28"
fi

check_1_1_29="1.1.29  - Ensure that the --client-ca-file argument is set as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--client-ca-file' >/dev/null 2>&1; then
    cafile=$(get_argument_value "$CIS_APISERVER_CMD" '--client-ca-file')
    pass "$check_1_1_29"
    pass "        * client-ca-file: $cafile"
else
    warn "$check_1_1_29"
fi

check_1_1_30="1.1.30  - Ensure that the --etcd-cafile argument is set as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--etcd-cafile' >/dev/null 2>&1; then
    cafile=$(get_argument_value "$CIS_APISERVER_CMD" '--etcd-cafile')
    pass "$check_1_1_30"
    pass "        * etcd-cafile: $cafile"
else
    warn "$check_1_1_30"
fi

check_1_1_31="1.1.31  - Ensure that the API Server only makes use of Strong Cryptographic Ciphers (Not Scored)"
if check_argument "$CIS_APISERVER_CMD" '--tls-cipher-suites' >/dev/null 2>&1; then
    ciphers=$(get_argument_value "$CIS_APISERVER_CMD" '--tls-cipher-suites'|cut -d " " -f 1)
    found=$(echo $ciphers| sed -rn '/(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305|TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305|TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)/p')
    if [ ! -z "$found" ]; then
      pass "$check_1_1_31"
    else
      warn "$check_1_1_31"
    fi
else
    warn "$check_1_1_31"
fi

check_1_1_32="1.1.32  - Ensure that the --authorization-mode argument includes Node (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--authorization-mode'| grep 'Node' >/dev/null 2>&1; then
    pass "$check_1_1_32"
else
    warn "$check_1_1_32"
fi

check_1_1_33="1.1.33  - Ensure that the admission control plugin NodeRestriction is set (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'NodeRestriction' >/dev/null 2>&1; then
    pass "$check_1_1_33"
else
    warn "$check_1_1_33"
fi

check_1_1_34="1.1.34  - Ensure that the --encryption-provider-config argument is set as appropriate (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--encryption-provider-config'| grep 'EncryptionConfig' >/dev/null 2>&1; then
    pass "$check_1_1_34"
else
    warn "$check_1_1_34"
fi

check_1_1_35="1.1.35  - Ensure that the encryption provider is set to aescbc (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--experimental-encryption-provider-config'| grep 'EncryptionConfig' >/dev/null 2>&1; then
    encryptionConfig=$(get_argument_value "$CIS_APISERVER_CMD" '--experimental-encryption-provider-config')
    if sed ':a;N;$!ba;s/\n/ /g' $encryptionConfig |grep "providers:\s* - aescbc" >/dev/null 2>&1; then
        pass "$check_1_1_35"
    else
        warn "$check_1_1_35"
    fi
else
    warn "$check_1_1_35"
fi

check_1_1_36="1.1.36  - Ensure that the admission control plugin EventRateLimit is set (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'EventRateLimit' >/dev/null 2>&1; then
    pass "$check_1_1_36"
    admissionctrl=$(get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins')
    pass "        * : $admissionctrl"
else
    warn "$check_1_1_36"
fi

check_1_1_37="1.1.37  - Ensure that the AdvancedAuditing argument is not set to false (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--feature-gates'| grep 'AdvancedAuditing=false' >/dev/null 2>&1; then
    warn "$check_1_1_37"
else
    pass "$check_1_1_37"
fi

check_1_1_38="1.1.38  - Ensure that the --request-timeout argument is set as appropriate (Scored)"
if check_argument "$CIS_APISERVER_CMD" '--request-timeout' >/dev/null 2>&1; then
    requestTimeout=$(get_argument_value "$CIS_APISERVER_CMD" '--request-timeout')
    warn "$check_1_1_38"
    warn "        * request-timeout: $requestTimeout"
else
    pass "$check_1_1_38"
fi

check_1_1_39="1.1.39  - Ensure that the --authorization-mode argument includes RBAC (Scored)"
if get_argument_value "$CIS_APISERVER_CMD" '--authorization-mode'| grep 'RBAC' >/dev/null 2>&1; then
    pass "$check_1_1_39"
else
    warn "$check_1_1_39"
fi


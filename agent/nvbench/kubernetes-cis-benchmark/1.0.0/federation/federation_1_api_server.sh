info "3.1 - Federation API Server"

check_3_1_1="3.1.1 	Ensure that the --anonymous-auth argument is set to false"
if check_argument 'federation-apiserver' '--anonymous-auth=false' >/dev/null 2>&1; then
    pass "$check_3_1_1"
else
    warn "$check_3_1_1"
fi

check_3_1_=2"3.1.2 	Ensure that the --basic-auth-file argument is not set"
if check_argument 'federation-apiserver' '--basic-auth-file' >/dev/null 2>&1; then
    warn "$check_3_1_2"
else
    pass "$check_3_1_2"
fi

check_3_1_3="3.1.3 	Ensure that the --insecure-allow-any-token argument is not set"
if check_argument 'federation-apiserver' '--insecure-allow-any-token' >/dev/null 2>&1; then
    warn "$check_3_1_3"
else
    pass "$check_3_1_3"
fi

check_3_1_4="3.1.4 	Ensure that the --insecure-bind-address argument is not set"
if check_argument 'federation-apiserver' '--insecure-bind-address' >/dev/null 2>&1; then
    warn "$check_3_1_4"
else
    pass "$check_3_1_4"
fi

check_3_1_5="3.1.5 	Ensure that the --insecure-port argument is set to 0"
if check_argument 'federation-apiserver' '--insecure-port' >/dev/null 2>&1; then
	port=$(get_argument_value 'federation-apiserver' '--insecure-port'|cut -d " " -f 1)
	if [ "$port" = "0" ]; then
  		pass "$check_3_1_5"
	else 
  		warn "$check_3_1_5"
       	warn "       * insecure-port: $port"
	fi
else
    warn "$check_3_1_5"
fi

check_3_1_6="3.1.6 	Ensure that the --secure-port argument is not set to 0"
if check_argument 'federation-apiserver' '--secure-port' >/dev/null 2>&1; then
	port=$(get_argument_value 'federation-apiserver' '--secure-port'|cut -d " " -f 1)
	if [ "$port" = "0" ]; then
  		warn "$check_3_1_6"
       	warn "       * secure-port: $port"
	else 
  		pass "$check_3_1_6"
	fi
else
    pass "$check_3_1_6"
fi

check_3_1_7="3.1.7 	Ensure that the --profiling argument is set to false"
if check_argument 'federation-apiserver' '--profiling=false' >/dev/null 2>&1; then
    pass "$check_3_1_7"
else
    warn "$check_3_1_7"
fi

check_3_1_8="3.1.8 	Ensure that the admission control policy is not set to AlwaysAdmit"
if get_argument_value 'federation-apiserver' '--admission-control'| grep 'AlwaysAdmit' >/dev/null 2>&1; then
    warn "$check_3_1_8"
else
    pass "$check_3_1_8"
fi

check_3_1_9="3.1.9 	Ensure that the admission control policy is set to NamespaceLifecycle"
if get_argument_value 'federation-apiserver' '--admission-control'| grep 'NamespaceLifecycle' >/dev/null 2>&1; then
    pass "$check_3_1_9"
else
    warn "$check_3_1_9"
fi

check_3_1_10="3.1.10 	Ensure that the --audit-log-path argument is set as appropriate"
if check_argument 'federation-apiserver' '--audit-log-path' >/dev/null 2>&1; then
	v=$(get_argument_value 'federation-apiserver' '--audit-log-path')
    pass "$check_3_1_10"
    pass "        * audit-log-path: $v"
else
    warn "$check_3_1_10"
fi

check_3_1_11="3.1.11 	Ensure that the --audit-log-maxage argument is set to 30 or as appropriate"
if check_argument 'federation-apiserver' '--audit-log-maxage' >/dev/null 2>&1; then
	v=$(get_argument_value 'federation-apiserver' '--audit-log-maxage'|cut -d " " -f 1)
	if [ "$v" = "30" ]; then
  		pass "$check_3_1_11"
       	pass "        * audit-log-maxage: $v"
	else 
  		warn "$check_3_1_11"
       	warn "        * audit-log-maxage: $v"
	fi 
else
    warn "$check_3_1_11"
fi

check_3_1_12="3.1.12 	Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate"
if check_argument 'federation-apiserver' '--audit-log-maxbackup' >/dev/null 2>&1; then
	v=$(get_argument_value 'federation-apiserver' '--audit-log-maxbackup' |cut -d " " -f 1)
	if [ "$v" = "10" ]; then
  		pass "$check_3_1_12"
       	pass "        * audit-log-maxbackup : $v"
	else 
  		warn "$check_3_1_12"
       	warn "        * audit-log-maxbackup : $v"
	fi 
else
    warn "$check_3_1_12"
fi

check_3_1_13="3.1.13 	Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate"
if check_argument 'federation-apiserver' '--audit-log-maxsize' >/dev/null 2>&1; then
	v=$(get_argument_value 'federation-apiserver' '--audit-log-maxsize' |cut -d " " -f 1)
	if [ "$v" = "100" ]; then
  		pass "$check_3_1_13"
       	pass "        * audit-log-maxsize : $v"
	else 
  		warn "$check_3_1_13"
       	warn "        * audit-log-maxsize : $v"
	fi 
else
    warn "$check_3_1_13"
fi

check_3_1_14="3.1.14 	Ensure that the --authorization-mode argument is not set to AlwaysAllow"
if get_argument_value 'federation-apiserver' '--authorization-mode'| grep 'AlwaysAllow' >/dev/null 2>&1; then
    warn "$check_3_1_14"
else
    pass "$check_3_1_14"
fi

check_3_1_15="3.1.15 	Ensure that the --token-auth-file parameter is not set"
if check_argument 'federation-apiserver' '--token-auth-file' >/dev/null 2>&1; then
    warn "$check_3_1_15"
else
    pass "$check_3_1_15"
fi

check_3_1_16="3.1.16 	Ensure that the --service-account-lookup argument is set to true"
if check_argument 'federation-apiserver' '--service-account-lookup=true' >/dev/null 2>&1; then
    pass "$check_3_1_16"
else
    warn "$check_3_1_16"
fi

check_3_1_17="3.1.17 	Ensure that the --service-account-key-file argument is set as appropriate"
if check_argument 'federation-apiserver' '--service-account-key-file' >/dev/null 2>&1; then
	v=$(get_argument_value 'federation-apiserver' '--service-account-key-file')
    pass "$check_3_1_17"
    pass "        * service-account-key-file: $v"
else
    warn "$check_3_1_17"
fi

check_3_1_18="3.1.18 	Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate"
if check_argument 'federation-apiserver' '--etcd-certfile' >/dev/null 2>&1; then
	if check_argument 'federation-apiserver' '--etcd-keyfile' >/dev/null 2>&1; then
		v1=$(get_argument_value 'federation-apiserver' '--etcd-certfile')
		v2=$(get_argument_value 'federation-apiserver' '--etcd-keyfile')
	    pass "$check_3_1_18"
	    pass "        * etcd-certfile: $v1"
	    pass "        * etcd-keyfile: $v2"
	else 
	    warn "$check_3_1_18"
	fi
else
    warn "$check_3_1_18"
fi

check_3_1_19="3.1.19 	Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate"
if check_argument 'federation-apiserver' '--tls-cert-file' >/dev/null 2>&1; then
	if check_argument 'federation-apiserver' '--tls-private-key-file' >/dev/null 2>&1; then
		v1=$(get_argument_value 'federation-apiserver' '--tls-cert-file')
		v2=$(get_argument_value 'federation-apiserver' '--tls-private-key-file')
	    pass "$check_3_1_19"
	    pass "        * tls-cert-file: $v1"
	    pass "        * tls-private-key-file: $v2"
	else 
	    warn "$check_3_1_19"
	fi
else
    warn "$check_3_1_19"
fi



#!/bin/sh

if [ -n "$nocolor" ] && [ "$nocolor" = "nocolor" ]; then
  bldred=''
  bldgrn=''
  bldblu=''
  bldylw=''
  bldcyn=''
  bldgry=''
  txtrst=''
else
  bldred='\033[1;31m'
  bldgrn='\033[1;32m'
  bldblu='\033[1;34m'
  bldylw='\033[1;33m'
  bldcyn='\033[1;36m'
  bldgry='\033[1;37m'
  txtrst='\033[0m'
fi

notScored="1.1.1, 1.1.12, 1.1.13, 1.1.31, 1.4.9, 1.4.10, 1.5.7, 1.6.1, 1.6.2, 1.6.3, 1.6.4, 1.6.5, 1.6.6, 1.6.7, 1.6.8,
1.7.1, 1.7.6, 1.7.7, 2.1.11, 2.1.14"
level2="1.3.6, 1.5.7, 1.6.1, 1.6.4, 1.6.5, 1.6.6, 1.6.7, 1.6.8,
 1.7.6, 1.7.7"

info () {

  s_txt=""
  if echo "$1" | grep -q "(Scored)"; then
    s_txt="${bldcyn}[Scored]${txtrst}"
  elif echo "$1" | grep -q "(Not Scored)"; then
    s_txt="${bldcyn}[Not Scored]${txtrst}"
  fi

  level_txt=""
  if [ ${#s_txt} -ne 0 ]; then
    idx=$(echo "$1" | cut -d " " -f 1)
    if echo "$level2" | grep -q "\<${idx}\>"; then
      level_txt="${bldgry}[Level 2]${txtrst}"
    else
      level_txt="${bldgry}[Level 1]${txtrst}"
    fi
  fi

  printf "%b\n" "${bldblu}[INFO]${txtrst}${level_txt}${s_txt} $1"
}

pass () {

  s_txt=""
  if echo "$1" | grep -q "(Scored)"; then
    s_txt="${bldcyn}[Scored]${txtrst}"
  elif echo "$1" | grep -q "(Not Scored)"; then
    s_txt="${bldcyn}[Not Scored]${txtrst}"
  fi

  level_txt=""
  if [ ${#s_txt} -ne 0 ]; then
    idx=$(echo "$1" | cut -d " " -f 1)
    if echo "$level2" | grep -q "\<${idx}\>"; then
      level_txt="${bldgry}[Level 2]${txtrst}"
    else
      level_txt="${bldgry}[Level 1]${txtrst}"
    fi
  fi

  printf "%b\n" "${bldgrn}[PASS]${txtrst}${level_txt}${s_txt} $1"

}

warn () {
  s_txt=""
  if echo "$1" | grep -q "(Scored)"; then
    s_txt="${bldcyn}[Scored]${txtrst}"
  elif echo "$1" | grep -q "(Not Scored)"; then
    s_txt="${bldcyn}[Not Scored]${txtrst}"
  fi

  level_txt=""
  if [ ${#s_txt} -ne 0 ]; then
    idx=$(echo "$1" | cut -d " " -f 1)
    if echo "$level2" | grep -q "\<${idx}\>"; then
      level_txt="${bldgry}[Level 2]${txtrst}"
    else
      level_txt="${bldgry}[Level 1]${txtrst}"
    fi
  fi

  printf "%b\n" "${bldred}[WARN]${txtrst}${level_txt}${s_txt} $1"

}

yell () {
  printf "%b\n" "${bldylw}$1${txtrst}\n"
}

yell "# ------------------------------------------------------------------------------
# Kubernetes CIS benchmark
#
# NeuVector, Inc. (c) 2020-
#
# NeuVector delivers an application and network intelligent container security
# solution that automatically adapts to protect running containers. Don’t let
# security concerns slow down your CI/CD processes.
# ------------------------------------------------------------------------------"

#get a process command line from /proc
get_command_line_args() {
    PROC="$1"
    len=${#PROC}
    if [ $len -gt 15 ]; then
		ps aux|grep  "$CMD "|grep -v "grep" |sed "s/.*$CMD \(.*\)/\1/g"
    else
        for PID in $(pgrep -n "$PROC")
        do
            tr "\0" " " < /proc/"$PID"/cmdline
        done
    fi
}

#get an argument value from command line
get_argument_value() {
    CMD="$1"
    OPTION="$2"

    get_command_line_args "$CMD" |
    sed \
        -e 's/\-\-/\n--/g' \
        |
    grep "^${OPTION}" |
    sed \
        -e "s/^${OPTION}=//g"
}

#check whether an argument exist in command line
check_argument() {
    CMD="$1"
    OPTION="$2"

    get_command_line_args "$CMD" |
    sed \
        -e 's/\-\-/\n--/g' \
        |
    grep "^${OPTION}"
}

CIS_KUBELET_CMD="<<<.Replace_kubelet_cmd>>>"
CIS_PROXY_CMD="<<<.Replace_proxy_cmd>>>"

if ps -ef | grep "$CIS_KUBELET_CMD" 2>/dev/null | grep -v "grep" >/dev/null 2>&1; then
	info "Kubernetes Worker Node Security Configuration"
else
	info "This node is not a Kubernetes worker node"
	exit 2
fi

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
exit 0;

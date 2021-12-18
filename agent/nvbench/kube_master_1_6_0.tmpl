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

level2="1.3.6, 2.7, 3.1.1, 3.2.2, 4.2.9, 5.2.9, 5.3.2, 5.4.2, 5.5.1, 5.7.2, 5.7.3, 5.7.4"
not_scored="1.1.9, 1.1.10, 1.1.20, 1.1.21, 1.2.1, 1.2.10, 1.2.12, 1.2.13, 1.2.33, 1.2.34, 1.2.35, 1.3.1, 2.7, 3.1.1, 3.2.2, 4,2.8, 4.2.9, 4.2.13, 5.1.1, 5.1.2, 5.1.3, 5.1.4, 5.1.6, 5.2.1, 5.2.6, 5.2.7, 5.2.8, 5.2.9, 5.3.1, 5.4.1, 5.4.2, 5.5.1, 5.7.1, 5.7.2, 5.7.3"
assessment_manual="1.1.9, 1.1.10, 1.1.20, 1.1.21, 1.2.1, 1.2.10, 1.2.12, 1.2.13, 1.2.33, 1.2.34, 1.2.35, 1.3.1, 2.7, 3.1.1, 3.2.1, 3.2.2, 4.1.3, 4.1.4, 4.1.6, 4.1.7, 4.1.8, 4.2.4, 4.2.5, 4.2.8, 4.2.9, 4.2.10, 4.2.11, 4.2.12, 4.2.13, 5.1.1, 5.1.2, 5.1.3, 5.1.4, 5.1.5, 5.1.6, 5.2.1, 5.2.2, 5.2.3, 5.2.4, 5.2.5, 5.2.6, 5.2.7, 5.2.8, 5.2.9, 5.3.1, 5.3.2, 5.4.1, 5.4.2, 5.5.1, 5.7.1, 5.7.2, 5.7.3, 5.7.4"

info () {

  s_txt=""
  if echo "$1" | grep -q "(Automated)"; then
    s_txt="${bldcyn}[Automated]${txtrst}"
  elif echo "$1" | grep -q "(Manual)"; then
    s_txt="${bldcyn}[Manual]${txtrst}"
  fi

  level_info=""
  scoring_info=""
  if [ ${#s_txt} -ne 0 ]; then
    idx=$(echo "$1" | cut -d " " -f 1)
    if echo "$level2" | grep -q "\<${idx}\>"; then
      level_info="${bldgry}[Level 2]${txtrst}"
    else
      level_info="${bldgry}[Level 1]${txtrst}"
    fi
    if echo "$not_scored" | grep -q "\<${idx}\>"; then
      scoring_info="${bldgry}[Not Scored]${txtrst}"
    else
      scoring_info="${bldgry}[Scored]${txtrst}"
    fi
  fi

  printf "%b\n" "${bldblu}[INFO]${txtrst}${level_info}${s_txt}${scoring_info} $1"
}

pass () {

  s_txt=""
  if echo "$1" | grep -q "(Automated)"; then
    s_txt="${bldcyn}[Automated]${txtrst}"
  elif echo "$1" | grep -q "(Manual)"; then
    s_txt="${bldcyn}[Manual]${txtrst}"
  fi

  level_info=""
  scoring_info=""
  if [ ${#s_txt} -ne 0 ]; then
    idx=$(echo "$1" | cut -d " " -f 1)
    if echo "$level2" | grep -q "\<${idx}\>"; then
      level_info="${bldgry}[Level 2]${txtrst}"
    else
      level_info="${bldgry}[Level 1]${txtrst}"
    fi
    if echo "$not_scored" | grep -q "\<${idx}\>"; then
      scoring_info="${bldgry}[Not Scored]${txtrst}"
    else
      scoring_info="${bldgry}[Scored]${txtrst}"
    fi
  fi

  printf "%b\n" "${bldgrn}[PASS]${txtrst}${level_info}${s_txt}${scoring_info} $1"

}

warn () {
  s_txt=""
  if echo "$1" | grep -q "(Automated)"; then
    s_txt="${bldcyn}[Automated]${txtrst}"
  elif echo "$1" | grep -q "(Manual)"; then
    s_txt="${bldcyn}[Manual]${txtrst}"
  fi

  level_info=""
  scoring_info=""
  if [ ${#s_txt} -ne 0 ]; then
    idx=$(echo "$1" | cut -d " " -f 1)
    if echo "$level2" | grep -q "\<${idx}\>"; then
      level_info="${bldgry}[Level 2]${txtrst}"
    else
      level_info="${bldgry}[Level 1]${txtrst}"
    fi
    if echo "$not_scored" | grep -q "\<${idx}\>"; then
      scoring_info="${bldgry}[Not Scored]${txtrst}"
    else
      scoring_info="${bldgry}[Scored]${txtrst}"
    fi
  fi

  printf "%b\n" "${bldred}[WARN]${txtrst}${level_info}${s_txt}${scoring_info} $1"

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

CIS_APISERVER_CMD="<<<.Replace_apiserver_cmd>>>"
CIS_MANAGER_CMD="<<<.Replace_manager_cmd>>>"
CIS_SCHEDULER_CMD="<<<.Replace_scheduler_cmd>>>"
CIS_ETCD_CMD="<<<.Replace_etcd_cmd>>>"
CIS_PROXY_CMD="<<<.Replace_proxy_cmd>>>"

if ps -ef | grep "$CIS_APISERVER_CMD" 2>/dev/null | grep -v "grep" >/dev/null 2>&1; then
	info "Kubernetes Master Node Security Configuration"
else
	info "This node is not a Kubernetes master node"
	exit 2
fi

info "1 - Control Plane Components"

info "1.1 - Master Node Configuration Files"

check_1_1_1="1.1.1  - Ensure that the API server pod specification file permissions are set to 644 or more restrictive (Automated)"
if [ -f "/etc/kubernetes/manifests/kube-apiserver.manifest" ]; then
    # kops
    file="/etc/kubernetes/manifests/kube-apiserver.manifest"
else
    file="/etc/kubernetes/manifests/kube-apiserver.yaml"
fi
if [ -f $file ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 640 -o "$(stat -c %a $file)" -eq 600 ]; then
    pass "$check_1_1_1"
  else
    warn "$check_1_1_1"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_1"
  info "     * File not found"
fi

check_1_1_2="1.1.2  - Ensure that the API server pod specification file ownership is set to root:root (Automated)"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_2"
  else
    warn "$check_1_1_2"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_2"
fi

check_1_1_3="1.1.3  - Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive (Automated)"
if [ -f "/etc/kubernetes/manifests/kube-controller-manager.manifest" ]; then
    # kops
    file="/etc/kubernetes/manifests/kube-controller-manager.manifest"
else
    file="/etc/kubernetes/manifests/kube-controller-manager.yaml"
fi

if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_1_1_3"
  else
    warn "$check_1_1_3"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_3"
  info "     * File not found"
fi

check_1_1_4="1.1.4  - Ensure that the controller manager pod specification file ownership is set to root:root (Automated)"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_4"
  else
    warn "$check_1_1_4"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_4"
fi

check_1_1_5="1.1.5  - Ensure that the scheduler pod specification file permissions are set to 644 or more restrictive (Automated)"
if [ -f "/etc/kubernetes/manifests/kube-scheduler.yaml" ]; then
    file="/etc/kubernetes/manifests/kube-scheduler.yaml"
else
    # kops
    file="/etc/kubernetes/manifests/kube-scheduler.manifest"
fi

if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_1_1_5"
  else
    warn "$check_1_1_5"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_5"
  info "     * File not found"
fi

check_1_1_6="1.1.6  - Ensure that the scheduler pod specification file ownership is set to root:root (Automated)"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_6"
  else
    warn "$check_1_1_6"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_6"
fi

check_1_1_7="1.1.7  - Ensure that the etcd pod specification file permissions are set to 644 or more restrictive (Automated)"
if [ -f "/etc/kubernetes/manifests/etcd.yaml" ]; then
    file="/etc/kubernetes/manifests/etcd.yaml"
else
    # kops
    file="/etc/kubernetes/manifests/etcd.manifest"
fi

if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_1_1_7"
  else
    warn "$check_1_1_7"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_7"
  info "     * File not found"
fi

check_1_1_8="1.1.8  - Ensure that the etcd pod specification file ownership is set to root:root (Automated)"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_8"
  else
    warn "$check_1_1_8"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_8"
fi

#todo find CNI file location
check_1_1_9="1.1.9  - Ensure that the Container Network Interface file permissions are set to 644 or more restrictive (Manual)"
info "$check_1_1_9
       Audit:
       Run the below command (based on the file location on your system) on the master node. For example,
       stat -c %a <path/to/cni/files>
       Verify that the permissions are 644 or more restrictive."

check_1_1_10="1.1.10  - Ensure that the Container Network Interface file ownership is set to root:root (Manual)"
info "$check_1_1_10
       Audit:
       Run the below command (based on the file location on your system) on the master node. For example,
       stat -c %U:%G <path/to/cni/files>
       Verify that the ownership is set to root:root."

check_1_1_11="1.1.11  - Ensure that the etcd data directory permissions are set to 700 or more restrictive (Automated)"
file=""
if check_argument "$CIS_ETCD_CMD" '--data-dir' >/dev/null 2>&1; then
    file=$(get_argument_value "$CIS_ETCD_CMD" '--data-dir'|cut -d " " -f 1)
fi
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 700 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_1_1_11"
  else
    warn "$check_1_1_11"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_11"
  info "     * etcd data directory not found."
fi

check_1_1_12="1.1.12  - Ensure that the etcd data directory ownership is set to etcd:etcd (Automated)"
if [ -f "$file" ]; then
  if [ "$(stat -c %U:%G $file)" = "etcd:etcd" ]; then
    pass "$check_1_1_12"
  else
    warn "$check_1_1_12"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_12"
  info "     * etcd data directory not found."
fi

check_1_1_13="1.1.13  - Ensure that the admin.conf file permissions are set to 644 or more restrictive (Automated)"
file="/etc/kubernetes/admin.conf"
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_1_1_13"
  else
    warn "$check_1_1_13"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_13"
  info "     * File not found"
fi

check_1_1_14="1.1.14  - Ensure that the admin.conf file ownership is set to root:root (Automated)"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_14"
  else
    warn "$check_1_1_14"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_14"
fi

check_1_1_15="1.1.15  - Ensure that the scheduler.conf file permissions are set to 644 or more restrictive (Automated)"
file="/etc/kubernetes/scheduler.conf"
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_1_1_15"
  else
    warn "$check_1_1_15"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_15"
  info "     * File not found"
fi

check_1_1_16="1.1.16  - Ensure that the scheduler.conf file ownership is set to root:root (Automated)"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_16"
  else
    warn "$check_1_1_16"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_16"
fi

check_1_1_17="1.1.17  - Ensure that the controller-manager.conf file permissions are set to 644 or more restrictive (Automated)"
file="/etc/kubernetes/controller-manager.conf"
if [ -f "$file" ]; then
  if [ "$(stat -c %a $file)" -eq 644 -o "$(stat -c %a $file)" -eq 600 -o "$(stat -c %a $file)" -eq 400 ]; then
    pass "$check_1_1_17"
  else
    warn "$check_1_1_17"
    warn "     * Wrong permissions for $file"
  fi
else
  info "$check_1_1_17"
  info "     * File not found"
fi

check_1_1_18="1.1.18  - Ensure that the controller-manager.conf file ownership is set to root:root (Automated)"
if [ -f "$file" ]; then
  if [ "$(stat -c %u%g $file)" -eq 00 ]; then
    pass "$check_1_1_18"
  else
    warn "$check_1_1_18"
    warn "     * Wrong ownership for $file"
  fi
else
  info "$check_1_1_18"
fi

check_1_1_19="1.1.19  - Ensure that the Kubernetes PKI directory and file ownership is set to root:root (Automated)"
file="/etc/kubernetes/pki/"
files=$(find $file)
pass=true
for f in ${files}; do
  if [ "$(stat -c %u%g $f)" != 00 ]; then
    pass=false;
    break;
  fi
done

if [ "$pass" = "true" ]; then
  pass "$check_1_1_19"
else
  warn "$check_1_1_19"
fi

check_1_1_20="1.1.20  - Ensure that the Kubernetes PKI certificate file permissions are set to 644 or more restrictive (Manual)"
files=$(find $file -name "*.crt")
pass=true
for f in ${files}; do
  if ! [ "$(stat -c %a $f)" -eq 644 -o "$(stat -c %a $f)" -eq 600 -o "$(stat -c %a $f)" -eq 400 ]; then
    pass=false;
    break;
  fi
done

if [ "$pass" = "true" ]; then
  pass "$check_1_1_20"
else
  warn "$check_1_1_20"
fi

check_1_1_21="1.1.21  - Ensure that the Kubernetes PKI key file permissions are set to 600 (Manual)"
files=$(find $file -name "*.key")
pass=true
for f in ${files}; do
  if ! [ "$(stat -c %a $f)" -eq 600 ]; then
    pass=false;
    break;
  fi
done

if [ "$pass" = "true" ]; then
  pass "$check_1_1_21"
else
  warn "$check_1_1_21"
fi

info "1.2 - API Server"

check_1_2_1="1.2.1  - Ensure that the --anonymous-auth argument is set to false (Manual)"
if check_argument "$CIS_APISERVER_CMD" '--anonymous-auth=false' >/dev/null 2>&1; then
    pass "$check_1_2_1"
else
    warn "$check_1_2_1"
fi

check_1_2_2="1.2.2  - Ensure that the --basic-auth-file argument is not set (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--basic-auth-file' >/dev/null 2>&1; then
    warn "$check_1_2_2"
else
    pass "$check_1_2_2"
fi

check_1_2_3="1.2.3  - Ensure that the --token-auth-file parameter is not set (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--token-auth-file' >/dev/null 2>&1; then
    warn "$check_1_2_3"
else
    pass "$check_1_2_3"
fi

check_1_2_4="1.2.4  - Ensure that the --kubelet-https argument is set to true (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--kubelet-https=false' >/dev/null 2>&1; then
    warn "$check_1_2_4"
else
    pass "$check_1_2_4"
fi

check_1_2_5="1.2.5  - Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--kubelet-client-certificate' >/dev/null 2>&1; then
    if check_argument "$CIS_APISERVER_CMD" '--kubelet-client-key' >/dev/null 2>&1; then
        certificate=$(get_argument_value "$CIS_APISERVER_CMD" '--kubelet-client-certificate')
        key=$(get_argument_value "$CIS_APISERVER_CMD" '--kubelet-client-key')
        pass "$check_1_2_5"
        pass "       * kubelet-client-certificate: $certificate"
        pass "       * kubelet-client-key: $key"
    else
        warn "$check_1_2_5"
    fi
else
    warn "$check_1_2_5"
fi

check_1_2_6="1.2.6  - Ensure that the --kubelet-certificate-authority argument is set as appropriate (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--kubelet-certificate-authority' >/dev/null 2>&1; then
    pass "$check_1_2_6"
else
    warn "$check_1_2_6"
fi

check_1_2_7="1.2.7  - Ensure that the --authorization-mode argument is not set to AlwaysAllow (Automated)"
if get_argument_value "$CIS_APISERVER_CMD" '--authorization-mode'| grep 'AlwaysAllow' >/dev/null 2>&1; then
    warn "$check_1_2_7"
else
    pass "$check_1_2_7"
fi

check_1_2_8="1.2.8  - Ensure that the --authorization-mode argument includes Node (Automated)"
if get_argument_value "$CIS_APISERVER_CMD" '--authorization-mode'| grep 'Node' >/dev/null 2>&1; then
    pass "$check_1_2_8"
else
    warn "$check_1_2_8"
fi

check_1_2_9="1.2.9  - Ensure that the --authorization-mode argument includes RBAC (Automated)"
if get_argument_value "$CIS_APISERVER_CMD" '--authorization-mode'| grep 'RBAC' >/dev/null 2>&1; then
    pass "$check_1_2_9"
else
    warn "$check_1_2_9"
fi

check_1_2_10="1.2.10  - Ensure that the admission control plugin EventRateLimit is set (Manual)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'EventRateLimit' >/dev/null 2>&1; then
    pass "$check_1_2_10"
else
    warn "$check_1_2_10"
fi

check_1_2_11="1.2.11  - Ensure that the admission control plugin AlwaysAdmit is not set (Automated)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'AlwaysAdmit' >/dev/null 2>&1; then
    warn "$check_1_2_11"
else
    pass "$check_1_2_11"
fi

check_1_2_12="1.2.12  - Ensure that the admission control plugin AlwaysPullImages is set (Manual)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'AlwaysPullImages' >/dev/null 2>&1; then
    pass "$check_1_2_12"
else
    warn "$check_1_2_12"
fi

check_1_2_13="1.2.13  - Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used (Manual)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'PodSecurityPolicy' >/dev/null 2>&1; then
    pass "$check_1_2_13"
else
  if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'SecurityContextDeny' >/dev/null 2>&1; then
    pass "$check_1_2_13"
  else
    warn "$check_1_2_13"
  fi
fi

check_1_2_14="1.2.14  - Ensure that the admission control plugin ServiceAccount is set (Automated)"
if get_argument_value "$CIS_APISERVER_CMD" '--disable-admission-plugins'| grep 'ServiceAccount' >/dev/null 2>&1; then
    warn "$check_1_2_14"
else
    pass "$check_1_2_14"
fi

check_1_2_15="1.2.15  - Ensure that the admission control plugin NamespaceLifecycle is set (Automated)"
if get_argument_value "$CIS_APISERVER_CMD" '--disable-admission-plugins'| grep 'NamespaceLifecycle' >/dev/null 2>&1; then
    warn "$check_1_2_15"
else
    pass "$check_1_2_15"
fi

check_1_2_16="1.2.16  - Ensure that the admission control plugin PodSecurityPolicy is set (Automated)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'PodSecurityPolicy' >/dev/null 2>&1; then
    pass "$check_1_2_16"
else
    warn "$check_1_2_16"
fi

check_1_2_17="1.2.17  - Ensure that the admission control plugin NodeRestriction is set (Automated)"
if get_argument_value "$CIS_APISERVER_CMD" '--enable-admission-plugins'| grep 'NodeRestriction' >/dev/null 2>&1; then
    pass "$check_1_2_17"
else
    warn "$check_1_2_17"
fi

check_1_2_18="1.2.18  - Ensure that the --insecure-bind-address argument is not set (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--insecure-bind-address' >/dev/null 2>&1; then
    warn "$check_1_2_18"
else
    pass "$check_1_2_18"
fi

check_1_2_19="1.2.19  - Ensure that the --insecure-port argument is set to 0 (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--insecure-port' >/dev/null 2>&1; then
    port=$(get_argument_value "$CIS_APISERVER_CMD" '--insecure-port'|cut -d " " -f 1)
    if [ "$port" = "0" ]; then
        pass "$check_1_2_19"
    else
        warn "$check_1_2_19"
        warn "       * insecure-port: $port"
    fi
else
    warn "$check_1_2_19"
fi

check_1_2_20="1.2.20  - Ensure that the --secure-port argument is not set to 0 (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--secure-port' >/dev/null 2>&1; then
    port=$(get_argument_value "$CIS_APISERVER_CMD" '--secure-port'|cut -d " " -f 1)
    if [ "$port" = "0" ]; then
        warn "$check_1_2_20"
        warn "       * secure-port: $port"
    else
        pass "$check_1_2_20"
    fi
else
    pass "$check_1_2_20"
fi

check_1_2_21="1.2.21  - Ensure that the --profiling argument is set to false (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--profiling=false' >/dev/null 2>&1; then
    pass "$check_1_2_21"
else
    warn "$check_1_2_21"
fi

check_1_2_22="1.2.22  - Ensure that the --audit-log-path argument is set (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--audit-log-path' >/dev/null 2>&1; then
    pass "$check_1_2_22"
else
    warn "$check_1_2_22"
fi

check_1_2_23="1.2.23  - Ensure that the --audit-log-maxage argument is set to 30 or as appropriate (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--audit-log-maxage' >/dev/null 2>&1; then
    maxage=$(get_argument_value "$CIS_APISERVER_CMD" '--audit-log-maxage'|cut -d " " -f 1)
    if [ "$maxage" -ge "30" ]; then
        pass "$check_1_2_23"
        pass "        * audit-log-maxage: $maxage"
    else
        warn "$check_1_2_23"
        warn "        * audit-log-maxage: $maxage"
    fi
else
    warn "$check_1_2_23"
fi

check_1_2_24="1.2.24  - Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--audit-log-maxbackup' >/dev/null 2>&1; then
    maxbackup=$(get_argument_value "$CIS_APISERVER_CMD" '--audit-log-maxbackup'|cut -d " " -f 1)
    if [ "$maxbackup" -ge "10" ]; then
        pass "$check_1_2_24"
        pass "        * audit-log-maxbackup: $maxbackup"
    else
        warn "$check_1_2_24"
        warn "        * audit-log-maxbackup: $maxbackup"
    fi
else
    warn "$check_1_2_24"
fi

check_1_2_25="1.2.25  - Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--audit-log-maxsize' >/dev/null 2>&1; then
    maxsize=$(get_argument_value "$CIS_APISERVER_CMD" '--audit-log-maxsize'|cut -d " " -f 1)
    if [ "$maxsize" -ge "100" ]; then
        pass "$check_1_2_25"
        pass "        * audit-log-maxsize: $maxsize"
    else
        warn "$check_1_2_25"
        warn "        * audit-log-maxsize: $maxsize"
    fi
else
    warn "$check_1_2_25"
fi

check_1_2_26="1.2.26  - Ensure that the --request-timeout argument is set as appropriate (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--request-timeout' >/dev/null 2>&1; then
    requestTimeout=$(get_argument_value "$CIS_APISERVER_CMD" '--request-timeout')
    warn "$check_1_2_26"
    warn "        * request-timeout: $requestTimeout"
else
    pass "$check_1_2_26"
fi

check_1_2_27="1.2.27  - Ensure that the --service-account-lookup argument is set to true (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--service-account-lookup=false' >/dev/null 2>&1; then
    warn "$check_1_2_27"
else
    pass "$check_1_2_27"
fi

check_1_2_28="1.2.28  - Ensure that the --service-account-key-file argument is set as appropriate (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--service-account-key-file' >/dev/null 2>&1; then
    file=$(get_argument_value "$CIS_APISERVER_CMD" '--service-account-key-file')
    pass "$check_1_2_28"
    pass "        * service-account-key-file: $file"
else
    warn "$check_1_2_28"
fi

check_1_2_29="1.2.29  - Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--etcd-certfile' >/dev/null 2>&1; then
    if check_argument "$CIS_APISERVER_CMD" '--etcd-keyfile' >/dev/null 2>&1; then
        certfile=$(get_argument_value "$CIS_APISERVER_CMD" '--etcd-certfile')
        keyfile=$(get_argument_value "$CIS_APISERVER_CMD" '--etcd-keyfile')
        pass "$check_1_2_29"
        pass "        * etcd-certfile: $certfile"
        pass "        * etcd-keyfile: $keyfile"
    else
        warn "$check_1_2_29"
    fi
else
    warn "$check_1_2_29"
fi

check_1_2_30="1.2.30  - Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--tls-cert-file' >/dev/null 2>&1; then
    if check_argument "$CIS_APISERVER_CMD" '--tls-private-key-file' >/dev/null 2>&1; then
        certfile=$(get_argument_value "$CIS_APISERVER_CMD" '--tls-cert-file')
        keyfile=$(get_argument_value "$CIS_APISERVER_CMD" '--tls-private-key-file')
        pass "$check_1_2_30"
        pass "        * tls-cert-file: $certfile"
        pass "        * tls-private-key-file: $keyfile"
    else
        warn "$check_1_2_30"
    fi
else
    warn "$check_1_2_30"
fi

check_1_2_31="1.2.31  - Ensure that the --client-ca-file argument is set as appropriate (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--client-ca-file' >/dev/null 2>&1; then
    cafile=$(get_argument_value "$CIS_APISERVER_CMD" '--client-ca-file')
    pass "$check_1_2_31"
    pass "        * client-ca-file: $cafile"
else
    warn "$check_1_2_31"
fi

check_1_2_32="1.2.32  - Ensure that the --etcd-cafile argument is set as appropriate (Automated)"
if check_argument "$CIS_APISERVER_CMD" '--etcd-cafile' >/dev/null 2>&1; then
    cafile=$(get_argument_value "$CIS_APISERVER_CMD" '--etcd-cafile')
    pass "$check_1_2_32"
    pass "        * etcd-cafile: $cafile"
else
    warn "$check_1_2_32"
fi

check_1_2_33="1.2.33  - Ensure that the --encryption-provider-config argument is set as appropriate (Manual)"
if get_argument_value "$CIS_APISERVER_CMD" '--encryption-provider-config'| grep 'EncryptionConfig' >/dev/null 2>&1; then
    pass "$check_1_2_33"
else
    warn "$check_1_2_33"
fi

check_1_2_34="1.2.34  - Ensure that encryption providers are appropriately configured (Manual)"
if check_argument "$CIS_APISERVER_CMD" '--encryption-provider-config' >/dev/null 2>&1; then
    encryptionConfig=$(get_argument_value "$CIS_APISERVER_CMD" '--encryption-provider-config')
    if [ -f "$encryptionConfig" ]; then
      if [ $(grep -c "\- aescbc:\|\- kms:\|\- secretbox:" $encryptionConfig) -ne 0 ]; then
        pass "$check_1_2_34"
      else
        warn "$check_1_2_34"
      fi
    else
      warn "$check_1_2_34"
    fi
else
    warn "$check_1_2_34"
fi
#if get_argument_value "$CIS_APISERVER_CMD" '--experimental-encryption-provider-config'| grep 'EncryptionConfig' >/dev/null 2>&1; then
#    encryptionConfig=$(get_argument_value "$CIS_APISERVER_CMD" '--experimental-encryption-provider-config')
#    if sed ':a;N;$!ba;s/\n/ /g' $encryptionConfig |grep "providers:\s* - aescbc" >/dev/null 2>&1; then
#        pass "$check_1_2_34"
#    else
#        warn "$check_1_2_34"
#    fi
#else
#    warn "$check_1_2_34"
#fi

check_1_2_35="1.2.35  - Ensure that the API Server only makes use of Strong Cryptographic Ciphers (Manual)"
if check_argument "$CIS_APISERVER_CMD" '--tls-cipher-suites' >/dev/null 2>&1; then
    ciphers=$(get_argument_value "$CIS_APISERVER_CMD" '--tls-cipher-suites'|cut -d " " -f 1)
    found=$(echo $ciphers| sed -rn '/(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305|TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305|TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)/p')
    if [ ! -z "$found" ]; then
      pass "$check_1_2_35"
    else
      warn "$check_1_2_35"
    fi
else
    warn "$check_1_2_35"
fi

info "1.3 - Controller Manager"

check_1_3_1="1.3.1  - Ensure that the --terminated-pod-gc-threshold argument is set as appropriate (Manual)"
# Filter out processes like "/bin/tee -a /var/log/kube-controller-manager.log"
# which exist on kops-managed clusters.
if check_argument "$CIS_MANAGER_CMD" '--terminated-pod-gc-threshold' >/dev/null 2>&1; then
    threshold=$(get_argument_value "$CIS_MANAGER_CMD" '--terminated-pod-gc-threshold')
    pass "$check_1_3_1"
    pass "       * terminated-pod-gc-threshold: $threshold"
else
    warn "$check_1_3_1"
fi

check_1_3_2="1.3.2  - Ensure that the --profiling argument is set to false (Automated)"
if check_argument "$CIS_MANAGER_CMD" '--profiling=false' >/dev/null 2>&1; then
    pass "$check_1_3_2"
else
    warn "$check_1_3_2"
fi

check_1_3_3="1.3.3  - Ensure that the --use-service-account-credentials argument is set to true (Automated)"
if check_argument "$CIS_MANAGER_CMD" '--use-service-account-credentials=true' >/dev/null 2>&1; then
    pass "$check_1_3_3"
else
    warn "$check_1_3_3"
fi

check_1_3_4="1.3.4  - Ensure that the --service-account-private-key-file argument is set as appropriate (Automated)"
if check_argument "$CIS_MANAGER_CMD" '--service-account-private-key-file' >/dev/null 2>&1; then
    keyfile=$(get_argument_value "$CIS_MANAGER_CMD" '--service-account-private-key-file')
    pass "$check_1_3_4"
    pass "       * service-account-private-key-file: $keyfile"
else
    warn "$check_1_3_4"
fi

check_1_3_5="1.3.5  - Ensure that the --root-ca-file argument is set as appropriate (Automated)"
if check_argument "$CIS_MANAGER_CMD" '--root-ca-file' >/dev/null 2>&1; then
    cafile=$(get_argument_value "$CIS_MANAGER_CMD" '--root-ca-file')
    pass "$check_1_3_5"
    pass "       * root-ca-file: $cafile"
else
    warn "$check_1_3_5"
fi

check_1_3_6="1.3.6  - Ensure that the RotateKubeletServerCertificate argument is set to true (Automated)"
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

check_1_3_7="1.3.7  - Ensure that the --bind-address argument is set to 127.0.0.1 (Automated)"
if get_argument_value "$CIS_MANAGER_CMD" '--bind-address'| grep '127.0.0.1' >/dev/null 2>&1; then
    pass "$check_1_3_7"
else
    warn "$check_1_3_7"
fi

info "1.4 - Scheduler"

check_1_4_1="1.4.1  - Ensure that the --profiling argument is set to false (Automated)"
if check_argument "$CIS_SCHEDULER_CMD" '--profiling=false' >/dev/null 2>&1; then
  	pass "$check_1_4_1"
else
  	warn "$check_1_4_1"
fi

check_1_4_2="1.4.2  - Ensure that the --bind-address argument is set to 127.0.0.1 (Automated)"
if get_argument_value "$CIS_SCHEDULER_CMD" '--bind-address'| grep '127.0.0.1' >/dev/null 2>&1; then
  	pass "$check_1_4_2"
else
  	warn "$check_1_4_2"
fi
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
info "3 - Control Plane Configuration"

info "3.1 - Authentication and Authorization"

check_3_1_1="3.1.1  - Client certificate authentication should not be used for users (Manual)"
info "$check_3_1_1"
info "        * Review user access to the cluster and ensure that users are not making use of Kubernetes client certificate authentication."

info "3.2 - Logging"

check_3_2_1="3.2.1 - Ensure that a minimal audit policy is created (Manual)"
if check_argument "$CIS_APISERVER_CMD" '--audit-policy-file' >/dev/null 2>&1; then
    auditPolicyFile=$(get_argument_value "$CIS_APISERVER_CMD" '--audit-policy-file')
    pass "$check_3_2_1"
    pass "        * audit-policy-file: $auditPolicyFile"
else
    warn "$check_3_2_1"
fi

check_3_2_2="3.2.2 - Ensure that the audit policy covers key security concerns (Manual)"
info "$check_3_2_2"
info "        * Access to Secrets managed by the cluster. Care should be taken to only log Metadata for requests to Secrets, ConfigMaps, and TokenReviews, in order to avoid the risk of logging sensitive data."
info "        * Modification of pod and deployment objects."
info "        * Use of pods/exec, pods/portforward, pods/proxy and services/proxy."
info "5 - Policies"
info "5.1 - RBAC and Service Accounts"

# Make the loop separator be a new-line in POSIX compliant fashion
set -f; IFS=$'
'

check_5_1_1="5.1.1  - Ensure that the cluster-admin role is only used where required (Manual)"
cluster_admins=$(kubectl get clusterrolebindings -o=custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT:.subjects[*].name)
info "$check_5_1_1"
for admin in $cluster_admins; do
 	info "     * $admin"
done

check_5_1_2="5.1.2  - Minimize access to secrets (Manual)"
policies=$(kubectl get psp)
info "$check_5_1_2"
for policy in $policies; do
	  info "     * $policy"
done

check_5_1_3="5.1.3  - Create administrative boundaries between resources using namespaces (Manual)"
namespaces=$(kubectl get namespaces)
info "$check_5_1_3"
for namespace in $namespaces; do
	info "     * $namespace"
done

check_5_1_4="5.1.4  - Create network segmentation using Network Policies (Manual)"
policies=$(kubectl get pods --namespace=kube-system)
info "$check_5_1_4"
for policy in $policies; do
	info "     * $policy"
done

check_5_1_5="5.1.5  - Avoid using Kubernetes Secrets (Manual)"
secrets=$(kubectl get secrets)
info "$check_5_1_5"
for secret in $secrets; do
	info "     * $secret"
done

#TODO
check_5_1_6="5.1.6  - Ensure that the seccomp profile is set to docker/default in your pod definitions (Manual)"
info "$check_5_1_6"
check_5_1_7="5.1.7  - Apply Security Context to Your Pods and Containers (Manual)"
info "$check_5_1_7"
check_5_1_8="5.1.8  - Configure Image Provenance using ImagePolicyWebhook admission controller (Manual)"
info "$check_5_1_8"
check_5_1_9="5.1.9  - Place compensating controls in the form of PSP and RBAC for privileged containers usage (Manual)"
info "$check_5_1_9"

info "5.2 - Pod Security Policies"

check_5_2_1="5.2.1  - Minimize the admission of privileged containers (Manual)"
info "$check_5_2_1"
check_5_2_2="5.2.2  - Minimize the admission of containers wishing to share the host process ID namespace (Manual)"
info "$check_5_2_2"
check_5_2_3="5.2.3  - Minimize the admission of containers wishing to share the host IPC namespace (Manual)"
info "$check_5_2_3"
check_5_2_4="5.2.4  - Minimize the admission of containers wishing to share the host network namespace (Manual)"
info "$check_5_2_4"
check_5_2_5="5.2.5  - Minimize the admission of containers with allowPrivilegeEscalation (Manual)"
info "$check_5_2_5"
check_5_2_6="5.2.6  - Minimize the admission of root containers (Manual)"
info "$check_5_2_6"
check_5_2_7="5.2.7  - Minimize the admission of containers with the NET_RAW capability (Manual)"
info "$check_5_2_7"
check_5_2_8="5.2.8  - Minimize the admission of containers with added capabilities (Manual)"
info "$check_5_2_8"
check_5_2_9="5.2.9  - Minimize the admission of containers with capabilities assigned (Manual)"
info "$check_5_2_9"

info "5.3 - Network Policies and CNI"
check_5_3_1="5.3.1  - Ensure that the CNI in use supports Network Policies (Manual)"
info "$check_5_3_1"
check_5_3_2="5.3.2  - Ensure that all Namespaces have Network Policies defined (Manual)"
info "$check_5_3_2"

info "5.4 - Secrets Management"
check_5_4_1="5.4.1  - Prefer using secrets as files over secrets as environment variables (Manual)"
info "$check_5_4_1"
check_5_4_2="5.4.2  - Consider external secret storage (Manual)"
info "$check_5_4_2"

info "5.5 - Extensible Admission Control"
check_5_5_1="5.5.1  - Configure Image Provenance using ImagePolicyWebhook admission controller (Manual)"
info "$check_5_5_1"

info "5.7 - General Policies"
check_5_7_1="5.7.1  - Create administrative boundaries between resources using namespaces (Manual)"
info "$check_5_7_1"
#todo remedition
check_5_7_2="5.7.2  - Ensure that the seccomp profile is set to docker/default in your pod definitions (Manual)"
info "$check_5_7_2"
check_5_7_3="5.7.3  - Apply Security Context to Your Pods and Containers (Manual)"
info "$check_5_6_3"
check_5_7_4="5.7.4  - The default namespace should not be used (Manual)"
info "$check_5_7_4"
exit 0;

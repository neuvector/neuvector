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


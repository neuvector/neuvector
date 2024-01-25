#!/bin/sh

if [ -n "$nocolor" ] && [ "$nocolor" = "nocolor" ]; then
  bldred=''
  bldgrn=''
  bldblu=''
  bldylw=''
  txtrst=''
else
  bldred='\033[1;31m'
  bldgrn='\033[1;32m'
  bldblu='\033[1;34m'
  bldylw='\033[1;33m'
  txtrst='\033[0m'
fi

info () {
  printf "%b\n" "${bldblu}[INFO]${txtrst} $1"
}

pass () {
  printf "%b\n" "${bldgrn}[PASS]${txtrst} $1"
}

warn () {
  printf "%b\n" "${bldred}[WARN]${txtrst} $1"
}

yell () {
  printf "%b\n" "${bldylw}$1${txtrst}\n"
}

yell "# ------------------------------------------------------------------------------
# Kubernetes CIS benchmark
#
# NeuVector, Inc. (c) 2016-
#
# NeuVector delivers an application and network intelligent container security
# solution that automatically adapts to protect running containers. Don’t let
# security concerns slow down your CI/CD processes.
# ------------------------------------------------------------------------------"

BASE_IMAGE_BIN_PATH="<<<.Replace_baseImageBin_path>>>"
export PATH="$PATH:$BASE_IMAGE_BIN_PATH/usr/bin:$BASE_IMAGE_BIN_PATH/bin"
export LD_LIBRARY_PATH="$BASE_IMAGE_BIN_PATH/bin:$LD_LIBRARY_PATH"
CONFIG_PREFIX="<<<.Replace_configPrefix_path>>>"

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
        -E "s/^${OPTION}(=|\s+)//g"
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

append_prefix() {
  local prefix="$1"
  local file="$2"

  # Remove any trailing slash from prefix
  prefix="${prefix%/}"

  # Remove a leading slash from file, if it exists
  file="${file#/}"

  # Concatenate and return the result
  echo "$prefix/$file"
}

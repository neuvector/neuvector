#!/bin/bash

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

#get an argument value from command line
get_argument_value_from_journal() {
    CMD="$1"
    OPTION="$2"

    echo "$CMD" |
    sed \
        -e 's/\-\-/\n--/g' \
        |
    grep "^${OPTION}" |
    sed \
        -e "s/^${OPTION}=//g"
}

#check whether an argument exist in command line
check_argument_from_journal() {
    CMD="$1"
    OPTION="$2"

    echo "$CMD" |
    sed \
        -e 's/\-\-/\n--/g' \
        |
    grep "^${OPTION}"
}

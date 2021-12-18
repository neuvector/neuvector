#!/bin/sh
# ------------------------------------------------------------------------------
# Kubenetes CIS benchmark
#
# Neuvector, Inc. (c) 2016-
#
# ------------------------------------------------------------------------------

usage () {
  cat <<EOF
  usage: ./master.sh [-b] [-c] VERSION

  -b           optional  Do not print colors
  VERSION      required  CIS benchmark version, for example: "4.3", "4.5"
EOF
}

while [ "$#" -ge 0 ]
do
  case $1 in
    -b) nocolor="nocolor"; shift;;
    4.3|4.5) ver=$1; break 2;;
    *) usage; exit 1;;
  esac
done

. ./helper_ocp.sh

# Check for required program(s)
req_progs='grep pgrep sed'
for p in $req_progs; do
  command -v "$p" >/dev/null 2>&1 || { printf "%s command not found.\n" "$p"; exit 1; }
done

OC_TOKEN=$(tail /var/run/secrets/kubernetes.io/serviceaccount/token)

# Load all the audits from master/ and run them
main () {

  for audit in $ver/enforcer/master/*.sh
  do
     . ./"$audit"
  done
}

main "$@"

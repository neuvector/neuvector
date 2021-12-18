#!/bin/sh
# ------------------------------------------------------------------------------
# Kubenetes CIS benchmark 
#
# Neuvector, Inc. (c) 2016-
#
# ------------------------------------------------------------------------------

usage () {
  cat <<EOF
  usage: ./worker.sh [-b] VERSION

  -b           optional  Do not print colors
  VERSION      required  CIS benchmark version, for example: "gke", "1.5.1", "1.4.1", "1.2.0", "1.0.0"
EOF
}

while [ "$#" -ge 0 ]
do
  case $1 in
    -b) nocolor="nocolor"; shift;;
    1.0.0|1.2.0|1.4.1|1.5.1|gke) ver=$1; break 2;;
    *) usage; exit 1;;
  esac
done

CIS_KUBELET_CMD=${CIS_KUBELET_CMD:-kubelet}
CIS_PROXY_CMD=${CIS_PROXY_CMD:-kube-proxy}
# Load dependencies
case $ver in
  gke)
    . ./helper_gke.sh
    ;;
  1.5.1)
    . ./helper1_5_1.sh
    ;;
  1.4.1)
    . ./helper1_4_1.sh
    ;;
  *)
    . ./helper.sh
    ;;
esac

# Check for required program(s)
req_progs='grep pgrep sed'
for p in $req_progs; do
  command -v "$p" >/dev/null 2>&1 || { printf "%s command not found.\n" "$p"; exit 1; }
done

# Load all the tests from worker/ and run them
main () {

  for audit in $ver/worker/*.sh
  do
     . ./"$audit"
  done
}

main "$@"

#!/bin/sh
# ------------------------------------------------------------------------------
# Kubenetes CIS benchmark 1.6
#
# Neuvector, Inc. (c) 2016-
#
# ------------------------------------------------------------------------------

# Load dependencies
. ./helper.sh

# Check for required program(s)
req_progs='grep'
for p in $req_progs; do
  command -v "$p" >/dev/null 2>&1 || { printf "%s command not found.\n" "$p"; exit 1; }
done

# Load all the tests from worker/ and run them
main () {
  for test in worker/worker_*.sh
  do
     . ./"$test"
  done
}

main "$@"

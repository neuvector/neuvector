#!/bin/sh
# ------------------------------------------------------------------------------
# Kubenetes CIS benchmark 1.6
#
# Neuvector, Inc. (c) 2016-
#
# NeuVector delivers an application and network intelligent container security 
# solution that automatically adapts to protect running containers. Don’t let 
# security concerns slow down your CI/CD processes.
# ------------------------------------------------------------------------------
# Load dependencies
. ./helper.sh

# Check for required program(s)
req_progs='grep'
for p in $req_progs; do
  command -v "$p" >/dev/null 2>&1 || { printf "%s command not found.\n" "$p"; exit 1; }
done

# Load all the tests from tests/ and run them
main () {
  info "3 - Federated Deployments"

  for test in federation/federation_*.sh
  do
     . ./"$test"
  done
}

main "$@"


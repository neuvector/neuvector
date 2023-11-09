#!/bin/bash

# Source the logger and utils scripts
source ../utils/logger.sh
source ../utils/utils.sh
source ../utils/style.sh

level2="1.3.6, 2.7, 3.1.1, 3.2.2, 4.2.9, 5.2.9, 5.3.2, 5.4.2, 5.5.1, 5.7.2, 5.7.3, 5.7.4"
not_scored="1.1.9, 1.1.10, 1.1.20, 1.1.21, 1.2.1, 1.2.10, 1.2.12, 1.2.13, 1.2.33, 1.2.34, 1.2.35, 1.3.1, 2.7, 3.1.1, 3.2.2, 4,2.8, 4.2.9, 4.2.13, 5.1.1, 5.1.2, 5.1.3, 5.1.4, 5.1.6, 5.2.1, 5.2.6, 5.2.7, 5.2.8, 5.2.9, 5.3.1, 5.4.1, 5.4.2, 5.5.1, 5.7.1, 5.7.2, 5.7.3"
assessment_manual="1.1.9, 1.1.10, 1.1.20, 1.1.21, 1.2.1, 1.2.10, 1.2.12, 1.2.13, 1.2.33, 1.2.34, 1.2.35, 1.3.1, 2.7, 3.1.1, 3.2.1, 3.2.2, 4.1.3, 4.1.4, 4.1.6, 4.1.7, 4.1.8, 4.2.4, 4.2.5, 4.2.8, 4.2.9, 4.2.10, 4.2.11, 4.2.12, 4.2.13, 5.1.1, 5.1.2, 5.1.3, 5.1.4, 5.1.5, 5.1.6, 5.2.1, 5.2.2, 5.2.3, 5.2.4, 5.2.5, 5.2.6, 5.2.7, 5.2.8, 5.2.9, 5.3.1, 5.3.2, 5.4.1, 5.4.2, 5.5.1, 5.7.1, 5.7.2, 5.7.3, 5.7.4"

NVBIN_PATH="<<<.Replace_nvbin_path>>>"
export PATH="$PATH:$NVBIN_PATH"
export LD_LIBRARY_PATH="/bin:$LD_LIBRARY_PATH"
CIS_KUBELET_CMD="kubelet"
CIS_PROXY_CMD="kube-proxy"


yell "# ------------------------------------------------------------------------------
# Kubernetes CIS benchmark
#
# NeuVector, Inc. (c) 2020-
#
# NeuVector delivers an application and network intelligent container security
# solution that automatically adapts to protect running containers. Don't let
# security concerns slow down your CI/CD processes.
# ------------------------------------------------------------------------------"


run_check() {
  local RUN_FOLDER=$1

  find $RUN_FOLDER -type f -name "*.yaml" | while read -r YAML_FILE; do
      # Get the number of groups
      NUM_GROUPS=$(yq e '.groups | length' "$YAML_FILE")

      # Iterate over each group
      for (( group_index=0; group_index<NUM_GROUPS; group_index++ )); do

        # Get the number of checks in the current group
        NUM_CHECKS=$(yq e ".groups[$group_index].checks | length" "$YAML_FILE")

        # Iterate over each check in the current group
        for (( check_index=0; check_index<NUM_CHECKS; check_index++ )); do
          id=$(yq e ".groups[$group_index].checks[$check_index].id" "$YAML_FILE")
          title=$(yq e ".groups[$group_index].checks[$check_index].title" "$YAML_FILE")
          audit=$(yq e ".groups[$group_index].checks[$check_index].audit" "$YAML_FILE")
          remediation=$(yq e ".groups[$group_index].checks[$check_index].remediation" "$YAML_FILE")


          eval "$audit"
        done
      done
  done
}

run_check "worker"
info "6 - Managed services"
info "6.1 - Image Registry and Image Scanning"

check_6_1_1="6.1.1  - Ensure Image Vulnerability Scanning using GCR Container Analysis or a third-party provider (Scored)"
info "$check_6_1_1"

check_6_1_2="6.1.2  - Minimize user access to GCR (Scored)"
info "$check_6_1_2"

check_6_1_3="6.1.3  - Minimize cluster access to read-only for GCR (Scored)"
info "$check_6_1_3"

check_6_1_4="6.1.4  - Minimize Container Registries to only those approved (Not Scored)"
info "$check_6_1_4"

info "6.2 - Identity and Access Management (IAM)"
check_6_2_1="6.2.1  - Ensure GKE clusters are not running using the Compute Engine default service account (Scored)"
info "$check_6_2_1"

check_6_2_2="6.2.2  - Prefer using dedicated GCP Service Accounts and Workload Identity (Not Scored)"
info "$check_6_2_2"

info "6.3 - Cloud Key Management Service (Cloud KMS)"
check_6_3_1="6.3.1  - Ensure Kubernetes Secrets are encrypted using keys managed in Cloud KMS (Scored)"
info "$check_6_3_1"

info "6.4 - Node Metadata"
check_6_4_1="6.4.1  - Ensure legacy Compute Engine instance metadata APIs are Disabled (Scored)"
info "$check_6_4_1"

check_6_4_2="6.4.2  - Ensure the GKE Metadata Server is Enabled (Not Scored)"
info "$check_6_4_2"

info "6.5 - Node Configuration and Maintenance"
check_6_5_1="6.5.1  - Ensure legacy Compute Engine instance metadata APIs are Disabled (Scored)"
info "$check_6_5_1"

check_6_5_2="6.5.2  - Ensure Node Auto-Repair is enabled for GKE nodes (Scored)"
info "$check_6_5_2"

check_6_5_3="6.5.3  - Ensure Node Auto-Upgrade is enabled for GKE nodes (Scored)"
info "$check_6_5_3"

check_6_5_4="6.5.4  - Automate GKE version management using Release Channels (Not Scored)"
info "$check_6_5_4"

check_6_5_5="6.5.5  - Ensure Shielded GKE Nodes are Enabled (Not Scored)"
info "$check_6_5_5"

check_6_5_6="6.5.6  - Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled (Not Scored)"
info "$check_6_5_6"

check_6_5_7="6.5.7  - Ensure Secure Boot for Shielded GKE Nodes is Enabled (Not Scored)"
info "$check_6_5_7"

info "6.6 - Cluster Networking"
check_6_6_1="6.6.1  - Enable VPC Flow Logs and Intranode Visibility (Not Scored)"
info "$check_6_6_1"

check_6_6_2="6.6.2  - Ensure use of VPC-native clusters (Scored)"
info "$check_6_6_2"

check_6_6_3="6.6.3  - Ensure Master Authorized Networks is Enabled (Scored)"
info "$check_6_6_3"

check_6_6_4="6.6.4  - Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled (Scored)"
info "$check_6_6_4"

check_6_6_5="6.6.5  - Ensure clusters are created with Private Nodes (Scored)"
info "$check_6_6_5"

check_6_6_6="6.6.6  - Consider firewalling GKE worker nodes (Not Scored)"
info "$check_6_6_6"

check_6_6_7="6.6.7  - Ensure Network Policy is Enabled and set as appropriate (Not Scored)"
info "$check_6_6_7"

check_6_6_8="6.6.8  - Ensure use of Google-managed SSL Certificates (Not Scored)"
info "$check_6_6_8"

info "6.7 - Cluster Networking"
check_6_7_1="6.7.1  - Ensure Stackdriver Kubernetes Logging and Monitoring is Enabled (Scored)"
info "$check_6_7_1"

check_6_7_2="6.7.2  - Enable Linux auditd logging (Not Scored)"
info "$check_6_7_2"

info "6.8 - Authentication and Authorization"

check_6_8_1="6.8.1  - Ensure Basic Authentication using static passwords is Disabled (Scored)"
info "$check_6_8_1"

check_6_8_2="6.8.2  - Ensure authentication using Client Certificates is Disabled (Scored)"
info "$check_6_8_2"

check_6_8_3="6.8.3  - Manage Kubernetes RBAC users with Google Groups for GKE (Not Scored)"
info "$check_6_8_3"

check_6_8_4="6.8.4  - Ensure Legacy Authorization (ABAC) is Disabled (Scored)"
info "$check_6_8_4"

info "6.9 - Storage"
check_6_9_1="6.9.1  - Enable Customer-Managed Encryption Keys (CMEK) for GKE Persistent Disks (PD) (Not Scored)"
info "$check_6_9_1"

info "6.10 - Other Cluster Configurations"

check_6_10_1="6.10.1  - Ensure Kubernetes Web UI is Disabled (Scored)"
info "$check_6_10_1"

check_6_10_2="6.10.2  - Ensure that Alpha clusters are not used for production workloads (Scored)"
info "$check_6_10_2"

check_6_10_3="6.10.3  - Ensure Pod Security Policy is Enabled and set as appropriate (Not Scored)"
info "$check_6_10_3"

check_6_10_4="6.10.4  - Consider GKE Sandbox for running untrusted workloads (Not Scored)"
info "$check_6_10_4"

check_6_10_5="6.10.5  - Ensure use of Binary Authorization (Scored)"
info "$check_6_10_5"

check_6_10_6="6.10.6  - Enable Cloud Security Command Center (Cloud SCC) (Not Scored)"
info "$check_6_10_6"

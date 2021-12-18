info "1 - Control Plane Components"

info "1.1 - Master Node Configuration Files"

check_1_1_1="1.1.1  - Ensure that the API server pod specification file permissions are set to 644 or more restrictive (Not Scored)"
info "$check_1_1_1"

check_1_1_2="1.1.2  - Ensure that the API server pod specification file ownership is set to root:root (Not Scored)"
info "$check_1_1_2"

check_1_1_3="1.1.3  - Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive (Not Scored)"
info "$check_1_1_3"

check_1_1_4="1.1.4  - Ensure that the controller manager pod specification file ownership is set to root:root (Not Scored)"
info "$check_1_1_4"

check_1_1_5="1.1.5  - Ensure that the scheduler pod specification file permissions are set to 644 or more restrictive (Not Scored)"
info "$check_1_1_5"

check_1_1_6="1.1.6  - Ensure that the scheduler pod specification file ownership is set to root:root (Not Scored)"
info "$check_1_1_6"

check_1_1_7="1.1.7  - Ensure that the etcd pod specification file permissions are set to 644 or more restrictive (Not Scored)"
info "$check_1_1_7"

check_1_1_8="1.1.8  - Ensure that the etcd pod specification file ownership is set to root:root (Not Scored)"
info "$check_1_1_8"

check_1_1_9="1.1.9  - Ensure that the Container Network Interface file permissions are set to 644 or more restrictive (Not Scored)"
info "$check_1_1_9"

check_1_1_10="1.1.10  - Ensure that the Container Network Interface file ownership is set to root:root (Not Scored)"
info "$check_1_1_10"

check_1_1_11="1.1.11  - Ensure that the etcd data directory permissions are set to 700 or more restrictive (Not Scored)"
info "$check_1_1_11"

check_1_1_12="1.1.12  - Ensure that the etcd data directory ownership is set to etcd:etcd (Not Scored)"
info "$check_1_1_12"

check_1_1_13="1.1.13  - Ensure that the admin.conf file permissions are set to 644 or more restrictive (Not Scored)"
info "$check_1_1_13"

check_1_1_14="1.1.14  - Ensure that the admin.conf file ownership is set to root:root (Not Scored)"
info "$check_1_1_14"

check_1_1_15="1.1.15  - Ensure that the scheduler.conf file permissions are set to 644 or more restrictive (Not Scored)"
info "$check_1_1_15"

check_1_1_16="1.1.16  - Ensure that the scheduler.conf file ownership is set to root:root (Not Scored) "
info "$check_1_1_16"

check_1_1_17="1.1.17  - Ensure that the controller-manager.conf file permissions are set to 644 or more restrictive (Not Scored)"
info "$check_1_1_17"

check_1_1_18="1.1.18  - Ensure that the controller-manager.conf file ownership is set to root:root (Not Scored) "
info "$check_1_1_18"

check_1_1_19="1.1.19  - Ensure that the Kubernetes PKI directory and file ownership is set to root:root (Not Scored)"
info "$check_1_1_19"

check_1_1_20="1.1.20  - Ensure that the Kubernetes PKI certificate file permissions are set to 644 or more restrictive (Not Scored)"
info "$check_1_1_20"

check_1_1_21="1.1.21  - Ensure that the Kubernetes PKI key file permissions are set to 600 (Not Scored)"
info "$check_1_1_21"

info "1.2 - API Server"

check_1_2_1="1.2.1  - Ensure that the --anonymous-auth argument is set to false (Not Scored)"
info "$check_1_2_1"

check_1_2_2="1.2.2  - Ensure that the --basic-auth-file argument is not set (Not Scored)"
info "$check_1_2_2"

check_1_2_3="1.2.3  - Ensure that the --token-auth-file parameter is not set (Not Scored)"
info "$check_1_2_3"

check_1_2_4="1.2.4  - Ensure that the --kubelet-https argument is set to true (Not Scored)"
info "$check_1_2_4"

check_1_2_5="1.2.5  - Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate (Not Scored)"
info "$check_1_2_5"

check_1_2_6="1.2.6  - Ensure that the --kubelet-certificate-authority argument is set as appropriate (Not Scored)"
info "$check_1_2_6"

check_1_2_7="1.2.7  - Ensure that the --authorization-mode argument is not set to AlwaysAllow (Not Scored)"
info "$check_1_2_7"

check_1_2_8="1.2.8  - Ensure that the --authorization-mode argument includes Node (Not Scored)"
info "$check_1_2_8"

check_1_2_9="1.2.9  - Ensure that the --authorization-mode argument includes RBAC (Not Scored)"
info "$check_1_2_9"

check_1_2_10="1.2.10  - Ensure that the admission control plugin EventRateLimit is set (Not Scored)"
info "$check_1_2_10"

check_1_2_11="1.2.11  - Ensure that the admission control plugin AlwaysAdmit is not set (Not Scored)"
info "$check_1_2_11"

check_1_2_12="1.2.12  - Ensure that the admission control plugin AlwaysPullImages is set (Not Scored)"
info "$check_1_2_12"

check_1_2_13="1.2.13  - Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used (Not Scored)"
info "$check_1_2_13"

check_1_2_14="1.2.14  - Ensure that the admission control plugin ServiceAccount is set (Not Scored)"
info "$check_1_2_14"

check_1_2_15="1.2.15  - Ensure that the admission control plugin NamespaceLifecycle is set (Not Scored)"
info "$check_1_2_15"

check_1_2_16="1.2.16  - Ensure that the admission control plugin PodSecurityPolicy is set (Not Scored)"
info "$check_1_2_16"

check_1_2_17="1.2.17  - Ensure that the admission control plugin NodeRestriction is set (Not Scored)"
info "$check_1_2_17"

check_1_2_18="1.2.18  - Ensure that the --insecure-bind-address argument is not set (Not Scored)"
info "$check_1_2_18"

check_1_2_19="1.2.19  - Ensure that the --insecure-port argument is set to 0 (Not Scored)"
info "$check_1_2_19"

check_1_2_20="1.2.20  - Ensure that the --secure-port argument is not set to 0 (Not Scored)"
info "$check_1_2_20"

check_1_2_21="1.2.21  - Ensure that the --profiling argument is set to false (Not Scored)"
info "$check_1_2_21"

check_1_2_22="1.2.22  - Ensure that the --audit-log-path argument is set (Not Scored)"
info "$check_1_2_22"

check_1_2_23="1.2.23  - Ensure that the --audit-log-maxage argument is set to 30 or as appropriate (Not Scored)"
info "$check_1_2_23"

check_1_2_24="1.2.24  - Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate (Not Scored)"
info "$check_1_2_24"

check_1_2_25="1.2.25  - Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate (Not Scored)"
info "$check_1_2_25"

check_1_2_26="1.2.26  - Ensure that the --request-timeout argument is set as appropriate (Not Scored)"
info "$check_1_2_26"

check_1_2_27="1.2.27  - Ensure that the --service-account-lookup argument is set to true (Not Scored)"
info "$check_1_2_27"

check_1_2_28="1.2.28  - Ensure that the --service-account-key-file argument is set as appropriate (Not Scored)"
info "$check_1_2_28"

check_1_2_29="1.2.29  - Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate (Not Scored)"
info "$check_1_2_29"

check_1_2_30="1.2.30  - Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Not Scored)"
info "$check_1_2_30"

check_1_2_31="1.2.31  - Ensure that the --client-ca-file argument is set as appropriate (Not Scored)"
info "$check_1_2_31"

check_1_2_32="1.2.32  - Ensure that the --etcd-cafile argument is set as appropriate (Not Scored)"
info "$check_1_2_32"

check_1_2_33="1.2.33  - Ensure that the --encryption-provider-config argument is set as appropriate (Not Scored)"
info "$check_1_2_33"

check_1_2_34="1.2.34  - Ensure that encryption providers are appropriately configured (Not Scored)"
info "$check_1_2_34"

check_1_2_35="1.2.35  - Ensure that the API Server only makes use of Strong Cryptographic Ciphers (Not Scored)"
info "$check_1_2_35"

info "1.3 - Controller Manager"

check_1_3_1="1.3.1  - Ensure that the --terminated-pod-gc-threshold argument is set as appropriate (Not Scored)"
info "$check_1_3_1"

check_1_3_2="1.3.2  - Ensure that the --profiling argument is set to false (Not Scored)"
info "$check_1_3_2"

check_1_3_3="1.3.3  - Ensure that the --use-service-account-credentials argument is set to true (Not Scored)"
info "$check_1_3_3"

check_1_3_4="1.3.4  - Ensure that the --service-account-private-key-file argument is set as appropriate (Not Scored)"
info "$check_1_3_4"

check_1_3_5="1.3.5  - Ensure that the --root-ca-file argument is set as appropriate (Not Scored)"
info "$check_1_3_5"

check_1_3_6="1.3.6  - Ensure that the RotateKubeletServerCertificate argument is set to true (Not Scored)"
info "$check_1_3_6"

check_1_3_7="1.3.7  - Ensure that the --bind-address argument is set to 127.0.0.1 (Not Scored)"
info "$check_1_3_7"

info "1.4 - Scheduler"

check_1_4_1="1.4.1  - Ensure that the --profiling argument is set to false (Not Scored)"
info "$check_1_4_1"

check_1_4_2="1.4.2  - Ensure that the --bind-address argument is set to 127.0.0.1 (Not Scored)"
info "$check_1_4_2"

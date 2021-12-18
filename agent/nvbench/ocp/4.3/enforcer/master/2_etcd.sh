info "2 - etcd"

check_2_1="2.1  - Ensure that the --cert-file and --key-file arguments are set as appropriate (Scored)"
file="/etc/kubernetes/manifests/etcd-member.yaml"
output_cert=$(grep "\(--cert-file=\)" $file)
output_key=$(grep "\(--key-file=\)" $file)
if [ -z "$output_cert" ] || [ -z "$output_key" ]; then
  warn "$check_2_1"
else
  pass "$check_2_1"
fi

check_2_2="2.2  - Ensure that the --client-cert-auth argument is set to true (Scored)"
file="/etc/kubernetes/manifests/etcd-member.yaml"
output=$(grep "\(--client-cert-auth=true\)" $file)
if [ -z "$output" ]; then
    warn "$check_2_2"
else
    pass "$check_2_2"
fi

check_2_3="2.3  - Ensure that the --auto-tls argument is not set to true (Scored)"
file="/etc/kubernetes/manifests/etcd-member.yaml"
output=$(grep "\(--auto-tls=true\)" $file)
if [ -z "$output" ]; then
    pass "$check_2_3"
else
    warn "$check_2_3"
fi

check_2_4="2.4  - Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate (Scored)"
file="/etc/kubernetes/manifests/etcd-member.yaml"
output_cert=$(grep "\(--peer-cert-file=\)" $file)
output_key=$(grep "\(--peer-key-file=\)" $file)
if [ -z "$output_cert" ] || [ -z "$output_key" ]; then
  warn "$check_2_4"
else
  pass "$check_2_4"
fi

check_2_5="2.5  - Ensure that the --peer-client-cert-auth argument is set to true (Scored)"
file="/etc/kubernetes/manifests/etcd-member.yaml"
output=$(grep "\(--peer-client-cert-auth=true\)" $file)
if [ -z "$output" ]; then
    warn "$check_2_5"
else
    pass "$check_2_5"
fi

check_2_6="2.6  - Ensure that the --peer-auto-tls argument is not set to true (Scored)"
file="/etc/kubernetes/manifests/etcd-member.yaml"
output=$(grep "\(--peer-auto-tls=true\)" $file)
if [ -z "$output" ]; then
    pass "$check_2_6"
else
    warn "$check_2_6"
fi

check_2_7="2.7  - Ensure that a unique Certificate Authority is used for etcd (Not Scored)"
file="/etc/kubernetes/manifests/etcd-member.yaml"
output=$(grep "\(--trusted-ca-file=/etc/ssl/etcd/ca.crt\)" $file)
if [ -z "$output" ]; then
    warn "$check_2_7"
else
    pass "$check_2_7"
fi

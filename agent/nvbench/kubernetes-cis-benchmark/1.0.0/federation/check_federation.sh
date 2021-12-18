
if ps -ef | grep federation-apiserver 2>/dev/null | grep -v "grep" >/dev/null 2>&1; then
	info "Kubernetes Federated Deployments"
else
	info "This node is not a Kubernetes Federated node"
	exit 2
fi


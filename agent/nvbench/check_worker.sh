
if ps -ef | grep "$CIS_KUBELET_CMD" 2>/dev/null | grep -v "grep" >/dev/null 2>&1; then
	info "Kubernetes Worker Node Security Configuration"
else
	info "This node is not a Kubernetes worker node"
	exit 2
fi


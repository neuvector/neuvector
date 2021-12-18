
if ps -ef | grep "$CIS_APISERVER_CMD" 2>/dev/null | grep -v "grep" >/dev/null 2>&1; then
	info "Kubernetes Master Node Security Configuration"
else
	info "This node is not a Kubernetes master node"
	exit 2
fi


---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

**Environment**
- Platform: [e.g. Kubernetes, OpenShift, Rancher, Managed k8s (AKS, EKS, GKE, IKS, ...), ...]
- Kubernetes/Platform Version(s): 
- NeuVector Version(s): [e.g., 5.5.3 ]
- Browsers Versions(s) for UI issues: [e.g., Chrome 147.0.7727.137 on Windows 11 ]

**Describe the bug**
A clear and concise description of what the bug is.  (If you are encountering a deployment error, check out the README or navigate to https://open-docs.neuvector.com for full deployment documentation.  Incorrect runtime is the most common reason for Controller and Enforcer CrashLoopBackOff events.)

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Container Logs**

<!-- 
NeuVector container logs can help identify issues more easily. Run the following commands to collect logs from all pods in the neuvector namespace. The logs will be saved in the current directory and archived as `/tmp/nvlogs.tar.gz`.

```bash
for pod in $(kubectl get pods -n neuvector --no-headers | awk '{print $1}'); do
    kubectl logs "$pod" --all-containers -n neuvector > "${pod}.log"
    kubectl logs "$pod" --all-containers --previous -n neuvector > "${pod}-previous.log"
done

tar -czvf /tmp/nvlogs.tar.gz *.log
```
-->


**Additional context**
Add any other context about the problem here.

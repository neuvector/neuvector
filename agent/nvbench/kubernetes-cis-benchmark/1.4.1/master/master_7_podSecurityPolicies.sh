check_1_7_1="1.7.1  - Do not admit privileged containers (Not Scored)"
names=$(kubectl get psp 2>/dev/null | sed 1,1d | cut -d " " -f 1)
result=""
for name in $names; do
  result=$(kubectl get psp $name -o=jsonpath='{.spec.privileged}'|grep true)
  if [ -z "$result" ]; then
    break;
  fi
done
if [ -z "$result" ]; then
  pass "$check_1_7_1"
else
  warn "$check_1_7_1"
fi

check_1_7_2="1.7.2  - Do not admit containers wishing to share the host process ID namespace (Scored)"
result=""
for name in $names; do
  result=$(kubectl get psp $name -o=jsonpath='{.spec.hostPID}'|grep true)
  if [ -z "$result" ]; then
    break;
  fi
done
if [ -z "$result" ]; then
  pass "$check_1_7_2"
else
  warn "$check_1_7_2"
fi

check_1_7_3="1.7.3  - Do not admit containers wishing to share the host IPC namespace (Scored)"
result=""
for name in $names; do
  result=$(kubectl get psp $name -o=jsonpath='{.spec.hostIPC}'|grep true)
  if [ -z "$result" ]; then
    break;
  fi
done
if [ -z "$result" ]; then
  pass "$check_1_7_3"
else
  warn "$check_1_7_3"
fi

check_1_7_4="1.7.4  - Do not admit containers wishing to share the host network namespace (Scored)"
result=""
for name in $names; do
  result=$(kubectl get psp $name -o=jsonpath='{.spec.hostNetwork}'|grep true)
  if [ -z "$result" ]; then
    break;
  fi
done
if [ -z "$result" ]; then
  pass "$check_1_7_4"
else
  warn "$check_1_7_4"
fi

check_1_7_5="1.7.5  - Do not admit containers with allowPrivilegeEscalation (Scored)"
result=""
for name in $names; do
  result=$(kubectl get psp $name -o=jsonpath='{.spec.allowPrivilegeEscalation}'|grep true)
  if [ -z "$result" ]; then
    break;
  fi
done
if [ -z "$result" ]; then
  pass "$check_1_7_5"
else
  warn "$check_1_7_5"
fi

check_1_7_6="1.7.6  - Do not admit root containers (Not Scored)"
result=""
for name in $names; do
  result=$(kubectl get psp $name -o=jsonpath='{.spec.runAsUser.rule}' | grep -v -E '(\<0\>)|(MustRunAsNonRoot)')
  if [ -z "$result" ]; then
    break;
  fi
done
if [ -z "$result" ]; then
  pass "$check_1_7_6"
else
  warn "$check_1_7_6"
fi

check_1_7_7="1.7.7  - Do not admit containers with dangerous capabilities (Not Scored)"
result=""
for name in $names; do
  result=$(kubectl get psp $name -o=jsonpath='{.spec.allowPrivilegeEscalation}'|grep true)
  if [ -z "$result" ]; then
    break;
  fi
done
if [ -z "$result" ]; then
  pass "$check_1_7_7"
else
  warn "$check_1_7_7"
fi


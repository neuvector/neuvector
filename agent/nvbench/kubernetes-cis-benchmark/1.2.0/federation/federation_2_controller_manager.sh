info "3.2 - Federation Controller Manager"

check_3_2_1="Ensure that the --profiling argument is set to false"
if check_argument 'federation-controller-manager' '--profiling=false' >/dev/null 2>&1; then
  	pass "$check_3_2_1"
else
  	warn "$check_3_2_1"
fi


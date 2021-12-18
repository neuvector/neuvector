info "1.2 - Scheduler"

check_1_2_1="1.2.1  - Ensure that the --profiling argument is set to false (Scored)"
if check_argument "$CIS_SCHEDULER_CMD" '--profiling=false' >/dev/null 2>&1; then
  	pass "$check_1_2_1"
else
  	warn "$check_1_2_1"
fi

check_1_2_2="1.2.2  - Ensure that the --address argument is set to 127.0.0.1 (Scored)"
if get_argument_value "$CIS_SCHEDULER_CMD" '--address'| grep '127.0.0.1' >/dev/null 2>&1; then
  	pass "$check_1_2_2"
else
  	warn "$check_1_2_2"
fi

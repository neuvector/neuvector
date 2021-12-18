#!/bin/sh

. ./common.sh

log_file="runall.detail.log"

# Check if time bin is non-empty
if [ -n "$test_time_bin" ]; then
	time_command="$test_time_bin -a -o $log_file"
else
	time_command=""
fi

for a in test_urcu_gc test_urcu_signal_gc test_urcu_mb_gc test_urcu_qsbr_gc \
	test_urcu_lgc test_urcu_signal_lgc test_urcu_mb_lgc test_urcu_qsbr_lgc \
	test_urcu test_urcu_signal test_urcu_mb test_urcu_qsbr \
	test_rwlock test_perthreadlock test_mutex; do
	echo "./${a} $*" | tee -a "$log_file"
	$time_command ./${a} $*
done


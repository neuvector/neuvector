#!/bin/sh

. ./common.sh

log_file="runall.detail.log"

# Check if time bin is non-empty
if [ -n "$test_time_bin" ]; then
	time_command="$test_time_bin -a -o $log_file"
else
	time_command=""
fi

#for a in test_urcu_gc test_urcu_gc_mb test_urcu_qsbr_gc; do
for a in test_urcu_gc; do
	echo "./${a} $*" | tee -a "$log_file"
	$time_command ./${a} $*
done


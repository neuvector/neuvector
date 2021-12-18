#
# This file is meant to be sourced from other tests scripts.
#

if [ -x "$URCU_TEST_TIME_BIN" ]; then
	test_time_bin="$URCU_TEST_TIME_BIN"
elif [ -x "/usr/bin/time" ]; then
	test_time_bin="/usr/bin/time"
else
	test_time_bin=""
fi


#!/bin/sh

readonly RC_TC=0
readonly RC_NOTC=1
readonly RC_OVS=2
readonly RC_ERROR=3

if [ ! -e /var/run/docker.sock ] && [ ! -e /run/containerd/containerd.sock ] && [ ! -e /var/run/crio/crio.sock ]; then
    echo "Cannot find container runtime socket"
    exit $RC_ERROR
fi

# In most cases, we don't require /lib/modules to be mounted, assume using tc driver
# is OK. Only when it's mounted (such as VIC), kernel module is checked.
if [ ! -e /lib/modules ]; then
    exit $RC_TC
fi

echo "Check TC kernel module ..."
module1=act_mirred
module2=act_pedit
modinfo "$module1" 2>&1 | grep "filename" > /dev/null
mod_mirred=$?
modinfo "$module2" 2>&1 | grep "filename" > /dev/null
mod_pedit=$?
if [ $mod_mirred = 0 ] && [ $mod_pedit = 0 ]; then
    echo "TC module located"
    exit $RC_TC
else
    if [ $mod_mirred != 0 ]; then 
        echo "module act_mirred not find."
    fi
    if [ $mod_pedit != 0 ]; then 
        echo "module act_pedit not find."
    fi
	exit $RC_NOTC
fi



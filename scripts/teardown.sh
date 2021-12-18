#!/bin/sh

# # If ovs is running inside container, stop it
# pid=`pgrep ovs-vswitchd`
# if [ $? == 0 ]; then
#     echo "Stop OVS daemon, pid=$pid ..."
#     kill -9 $pid
#     rm /var/run/openvswitch/ovs-vswitchd.pid
# fi

# pid=`pgrep ovsdb-server`
# if [ $? == 0 ]; then
#     echo "Stop OVS DB, pid=$pid ..."
#     kill -9 $pid
#     rm /var/run/openvswitch/ovsdb-server.pid
# fi

echo "Leave the cluster"
consul leave
exit 0

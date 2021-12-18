#!/bin/sh

REPLACE_DAEMON_OPTS="Replace_docker_daemon_opts"
REPLACE_CONTAINER_LIST="Replace_container_list"

HOSTFILE="host.tmpl"
HOSTTMP="/tmp/host.tmp"
CNTRFILE="container.tmpl"
CNTRTMP="/tmp/container.tmp"

rm -f $HOSTFILE $CNTRFILE

echo "==> generate $HOSTFILE"

cat docker-bench-security/functions/functions_lib.sh > $HOSTTMP
sed "s/get_command_line_args \"\$line_arg\"/echo \"<<<.$REPLACE_DAEMON_OPTS>>>\"/" docker-bench-security/functions/helper_lib.sh >> $HOSTTMP
cat docker-bench-security/functions/output_lib.sh >> $HOSTTMP
cat docker-bench-security/tests/1_host_configuration.sh >> $HOSTTMP
cat docker-bench-security/tests/2_docker_daemon_configuration.sh >> $HOSTTMP
cat docker-bench-security/tests/3_docker_daemon_configuration_files.sh >> $HOSTTMP
cat docker-bench-security/tests/4_container_images.sh >> $HOSTTMP
cat docker-bench-security/tests/6_docker_security_operations.sh >> $HOSTTMP
echo  "host_configuration" >> $HOSTTMP
echo  "docker_daemon_configuration" >> $HOSTTMP
echo  "docker_daemon_files" >> $HOSTTMP
echo  "check_4_2" >> $HOSTTMP
echo  "check_4_3" >> $HOSTTMP
echo  "check_4_4" >> $HOSTTMP
echo  "check_4_5" >> $HOSTTMP
echo  "check_4_6" >> $HOSTTMP
echo  "check_4_7" >> $HOSTTMP
echo  "check_4_8" >> $HOSTTMP
echo  "check_4_9" >> $HOSTTMP
echo  "check_4_10" >> $HOSTTMP
echo  "check_4_11" >> $HOSTTMP
echo  "docker_security_operations" >> $HOSTTMP
echo  "exit 0;" >> $HOSTTMP

echo "==> generate $CNTRFILE"

cat docker-bench-security/functions/functions_lib.sh > $CNTRTMP
echo "<<<.$REPLACE_CONTAINER_LIST>>>\n" >> $CNTRTMP
sed "s/get_command_line_args \"\$line_arg\"/echo \"<<<.$REPLACE_DAEMON_OPTS>>>\"/" docker-bench-security/functions/helper_lib.sh  >> $CNTRTMP
cat docker-bench-security/functions/output_lib.sh >> $CNTRTMP
cat docker-bench-security/tests/4_container_images.sh >> $CNTRTMP
cat docker-bench-security/tests/5_container_runtime.sh >> $CNTRTMP
echo  "check_4_1" >> $CNTRTMP
echo  "container_runtime" >> $CNTRTMP
echo  "exit 0;" >> $CNTRTMP


grep $REPLACE_DAEMON_OPTS $HOSTTMP >/dev/null 2>&1 || { echo "Failed to replace docker daemon opts - $HOSTFILE"; exit 1; }
grep $REPLACE_CONTAINER_LIST $CNTRTMP >/dev/null 2>&1 || { echo "Failed to replace container list opts - $CNTRFILE"; exit 1; }
grep $REPLACE_DAEMON_OPTS $CNTRTMP >/dev/null 2>&1 || { echo "Failed to replace docker daemon opts - $CNTRFILE"; exit 1; }

mv $HOSTTMP $HOSTFILE
mv $CNTRTMP $CNTRFILE

#kubernetes cis 1.0.0
REPLACE_CIS_APISERVER_CMD="Replace_apiserver_cmd"
REPLACE_CIS_MANAGER_CMD="Replace_manager_cmd"
REPLACE_CIS_SCHEDULER_CMD="Replace_scheduler_cmd"
REPLACE_CIS_ETCD_CMD="Replace_etcd_cmd"
REPLACE_CIS_KUBELET_CMD="Replace_kubelet_cmd"
REPLACE_CIS_PROXY_CMD="Replace_proxy_cmd"

MASTER="kube_master_1_0_0.tmpl"
WORKER="kube_worker_1_0_0.tmpl"
echo "==> generate $MASTER and $WORKER"

cat kubernetes-cis-benchmark/helper.sh > $MASTER

echo "CIS_APISERVER_CMD=\"<<<.$REPLACE_CIS_APISERVER_CMD>>>\"" >> $MASTER
echo "CIS_MANAGER_CMD=\"<<<.$REPLACE_CIS_MANAGER_CMD>>>\"" >> $MASTER
echo "CIS_SCHEDULER_CMD=\"<<<.$REPLACE_CIS_SCHEDULER_CMD>>>\"" >> $MASTER
echo "CIS_ETCD_CMD=\"<<<.$REPLACE_CIS_ETCD_CMD>>>\"" >> $MASTER

cat check_master.sh >> $MASTER

cat kubernetes-cis-benchmark/1.0.0/master/master_1_api_server.sh >> $MASTER
cat kubernetes-cis-benchmark/1.0.0/master/master_2_scheduler.sh >> $MASTER
cat kubernetes-cis-benchmark/1.0.0/master/master_3_contoller_manager.sh >> $MASTER
cat kubernetes-cis-benchmark/1.0.0/master/master_4_configuration_files.sh >> $MASTER
cat kubernetes-cis-benchmark/1.0.0/master/master_5_etcd.sh >> $MASTER
cat kubernetes-cis-benchmark/1.0.0/master/master_6_general_security_primitives.sh >> $MASTER
echo  "exit 0;" >> $MASTER

cat kubernetes-cis-benchmark/helper.sh > $WORKER
echo "CIS_KUBELET_CMD=\"<<<.$REPLACE_CIS_KUBELET_CMD>>>\"" >> $WORKER
cat check_worker.sh >> $WORKER
cat kubernetes-cis-benchmark/1.0.0/worker/worker_1_kubelet.sh >> $WORKER
cat kubernetes-cis-benchmark/1.0.0/worker/worker_2_configure_files.sh >> $WORKER
echo  "exit 0;" >> $WORKER


#kubernetes cis 1.2.0
MASTER="kube_master_1_2_0.tmpl"
WORKER="kube_worker_1_2_0.tmpl"
echo "==> generate $MASTER and $WORKER"
cat kubernetes-cis-benchmark/helper.sh > $MASTER

echo "CIS_APISERVER_CMD=\"<<<.$REPLACE_CIS_APISERVER_CMD>>>\"" >> $MASTER
echo "CIS_MANAGER_CMD=\"<<<.$REPLACE_CIS_MANAGER_CMD>>>\"" >> $MASTER
echo "CIS_SCHEDULER_CMD=\"<<<.$REPLACE_CIS_SCHEDULER_CMD>>>\"" >> $MASTER
echo "CIS_ETCD_CMD=\"<<<.$REPLACE_CIS_ETCD_CMD>>>\"" >> $MASTER

cat check_master.sh >> $MASTER
cat kubernetes-cis-benchmark/1.2.0/master/master_1_api_server.sh >> $MASTER
cat kubernetes-cis-benchmark/1.2.0/master/master_2_scheduler.sh >> $MASTER
cat kubernetes-cis-benchmark/1.2.0/master/master_3_contoller_manager.sh >> $MASTER
cat kubernetes-cis-benchmark/1.2.0/master/master_4_configuration_files.sh >> $MASTER
cat kubernetes-cis-benchmark/1.2.0/master/master_5_etcd.sh >> $MASTER
cat kubernetes-cis-benchmark/1.2.0/master/master_6_general_security_primitives.sh >> $MASTER
echo  "exit 0;" >> $MASTER

cat kubernetes-cis-benchmark/helper.sh > $WORKER
echo "CIS_KUBELET_CMD=\"<<<.$REPLACE_CIS_KUBELET_CMD>>>\"" >> $WORKER
cat check_worker.sh >> $WORKER
cat kubernetes-cis-benchmark/1.2.0/worker/worker_1_kubelet.sh >> $WORKER
cat kubernetes-cis-benchmark/1.2.0/worker/worker_2_configure_files.sh >> $WORKER
echo  "exit 0;" >> $WORKER

#kubernetes cis 1.4.1
MASTER="kube_master_1_4_1.tmpl"
WORKER="kube_worker_1_4_1.tmpl"
echo "==> generate $MASTER and $WORKER"
cat kubernetes-cis-benchmark/helper1_4_1.sh > $MASTER

echo "CIS_APISERVER_CMD=\"<<<.$REPLACE_CIS_APISERVER_CMD>>>\"" >> $MASTER
echo "CIS_MANAGER_CMD=\"<<<.$REPLACE_CIS_MANAGER_CMD>>>\"" >> $MASTER
echo "CIS_SCHEDULER_CMD=\"<<<.$REPLACE_CIS_SCHEDULER_CMD>>>\"" >> $MASTER
echo "CIS_ETCD_CMD=\"<<<.$REPLACE_CIS_ETCD_CMD>>>\"" >> $MASTER
echo "CIS_PROXY_CMD=\"<<<.$REPLACE_CIS_PROXY_CMD>>>\"" >> $MASTER

cat check_master.sh >> $MASTER
cat kubernetes-cis-benchmark/1.4.1/master/master_1_api_server.sh >> $MASTER
cat kubernetes-cis-benchmark/1.4.1/master/master_2_scheduler.sh >> $MASTER
cat kubernetes-cis-benchmark/1.4.1/master/master_3_contoller_manager.sh >> $MASTER
cat kubernetes-cis-benchmark/1.4.1/master/master_4_configuration_files.sh >> $MASTER
cat kubernetes-cis-benchmark/1.4.1/master/master_5_etcd.sh >> $MASTER
cat kubernetes-cis-benchmark/1.4.1/master/master_6_general_security_primitives.sh >> $MASTER
cat kubernetes-cis-benchmark/1.4.1/master/master_7_podSecurityPolicies.sh >> $MASTER
echo  "exit 0;" >> $MASTER

cat kubernetes-cis-benchmark/helper1_4_1.sh > $WORKER
echo "CIS_KUBELET_CMD=\"<<<.$REPLACE_CIS_KUBELET_CMD>>>\"" >> $WORKER
echo "CIS_PROXY_CMD=\"<<<.$REPLACE_CIS_PROXY_CMD>>>\"" >> $WORKER
cat check_worker.sh >> $WORKER
cat kubernetes-cis-benchmark/1.4.1/worker/worker_1_kubelet.sh >> $WORKER
cat kubernetes-cis-benchmark/1.4.1/worker/worker_2_configure_files.sh >> $WORKER
echo  "exit 0;" >> $WORKER

#kubernetes cis 1.5.1
MASTER="kube_master_1_5_1.tmpl"
WORKER="kube_worker_1_5_1.tmpl"
echo "==> generate $MASTER and $WORKER"
cat kubernetes-cis-benchmark/helper1_5_1.sh > $MASTER

echo "CIS_APISERVER_CMD=\"<<<.$REPLACE_CIS_APISERVER_CMD>>>\"" >> $MASTER
echo "CIS_MANAGER_CMD=\"<<<.$REPLACE_CIS_MANAGER_CMD>>>\"" >> $MASTER
echo "CIS_SCHEDULER_CMD=\"<<<.$REPLACE_CIS_SCHEDULER_CMD>>>\"" >> $MASTER
echo "CIS_ETCD_CMD=\"<<<.$REPLACE_CIS_ETCD_CMD>>>\"" >> $MASTER
echo "CIS_PROXY_CMD=\"<<<.$REPLACE_CIS_PROXY_CMD>>>\"" >> $MASTER

cat check_master.sh >> $MASTER
cat kubernetes-cis-benchmark/1.5.1/master/1_control_plane_components.sh >> $MASTER
cat kubernetes-cis-benchmark/1.5.1/master/2_etcd.sh >> $MASTER
cat kubernetes-cis-benchmark/1.5.1/master/3_control_plane_configuration.sh >> $MASTER
echo  "exit 0;" >> $MASTER

cat kubernetes-cis-benchmark/helper1_5_1.sh > $WORKER
echo "CIS_KUBELET_CMD=\"<<<.$REPLACE_CIS_KUBELET_CMD>>>\"" >> $WORKER
echo "CIS_PROXY_CMD=\"<<<.$REPLACE_CIS_PROXY_CMD>>>\"" >> $WORKER
cat check_worker.sh >> $WORKER
cat kubernetes-cis-benchmark/1.5.1/worker/4_worker_nodes.sh >> $WORKER
echo  "exit 0;" >> $WORKER

#kubernetes cis 1.6.0
MASTER="kube_master_1_6_0.tmpl"
WORKER="kube_worker_1_6_0.tmpl"
echo "==> generate $MASTER and $WORKER"
cat kubernetes-cis-benchmark/helper1_6_0.sh > $MASTER

echo "CIS_APISERVER_CMD=\"<<<.$REPLACE_CIS_APISERVER_CMD>>>\"" >> $MASTER
echo "CIS_MANAGER_CMD=\"<<<.$REPLACE_CIS_MANAGER_CMD>>>\"" >> $MASTER
echo "CIS_SCHEDULER_CMD=\"<<<.$REPLACE_CIS_SCHEDULER_CMD>>>\"" >> $MASTER
echo "CIS_ETCD_CMD=\"<<<.$REPLACE_CIS_ETCD_CMD>>>\"" >> $MASTER
echo "CIS_PROXY_CMD=\"<<<.$REPLACE_CIS_PROXY_CMD>>>\"" >> $MASTER

cat check_master.sh >> $MASTER
cat kubernetes-cis-benchmark/1.6.0/master/1_control_plane_components.sh >> $MASTER
cat kubernetes-cis-benchmark/1.6.0/master/2_etcd.sh >> $MASTER
cat kubernetes-cis-benchmark/1.6.0/master/3_control_plane_configuration.sh >> $MASTER
cat kubernetes-cis-benchmark/1.6.0/master/5_policies.sh >> $MASTER
echo  "exit 0;" >> $MASTER

cat kubernetes-cis-benchmark/helper1_6_0.sh > $WORKER
echo "CIS_KUBELET_CMD=\"<<<.$REPLACE_CIS_KUBELET_CMD>>>\"" >> $WORKER
echo "CIS_PROXY_CMD=\"<<<.$REPLACE_CIS_PROXY_CMD>>>\"" >> $WORKER
cat check_worker.sh >> $WORKER
cat kubernetes-cis-benchmark/1.6.0/worker/4_worker_nodes.sh >> $WORKER
echo  "exit 0;" >> $WORKER

#GKE cis 1.0.0
MASTER="kube_master_gke_1_0_0.tmpl"
WORKER="kube_worker_gke_1_0_0.tmpl"
echo "==> generate $MASTER and $WORKER"
cat kubernetes-cis-benchmark/helper_gke.sh > $MASTER

echo "CIS_APISERVER_CMD=\"<<<.$REPLACE_CIS_APISERVER_CMD>>>\"" >> $MASTER
echo "CIS_MANAGER_CMD=\"<<<.$REPLACE_CIS_MANAGER_CMD>>>\"" >> $MASTER
echo "CIS_SCHEDULER_CMD=\"<<<.$REPLACE_CIS_SCHEDULER_CMD>>>\"" >> $MASTER
echo "CIS_ETCD_CMD=\"<<<.$REPLACE_CIS_ETCD_CMD>>>\"" >> $MASTER
echo "CIS_PROXY_CMD=\"<<<.$REPLACE_CIS_PROXY_CMD>>>\"" >> $MASTER

cat check_master.sh >> $MASTER
cat kubernetes-cis-benchmark/gke/master/1_control_plane_components.sh >> $MASTER
cat kubernetes-cis-benchmark/gke/master/2_etcd.sh >> $MASTER
cat kubernetes-cis-benchmark/gke/master/3_control_plane_configuration.sh >> $MASTER
echo  "exit 0;" >> $MASTER

cat kubernetes-cis-benchmark/helper_gke.sh > $WORKER
echo "CIS_KUBELET_CMD=\"<<<.$REPLACE_CIS_KUBELET_CMD>>>\"" >> $WORKER
echo "CIS_PROXY_CMD=\"<<<.$REPLACE_CIS_PROXY_CMD>>>\"" >> $WORKER
cat check_worker.sh >> $WORKER
cat kubernetes-cis-benchmark/gke/worker/4_worker_nodes.sh >> $WORKER

#OC cis 4.3
MASTER="kube_master_ocp_4_3.tmpl"
WORKER="kube_worker_ocp_4_3.tmpl"
echo "==> generate $MASTER and $WORKER"

cat ocp/helper_ocp.sh > $MASTER
cat ocp/4.3/enforcer/master/1_control_plane_components.sh >> $MASTER
cat ocp/4.3/enforcer/master/2_etcd.sh >> $MASTER
cat ocp/4.3/enforcer/master/3_control_plane_configuration.sh >> $MASTER
cat ocp/4.3/enforcer/master/5_policies.sh >> $MASTER
echo  "exit 0;" >> $MASTER

cat ocp/helper_ocp.sh > $WORKER
cat ocp/4.3/enforcer//worker/4_worker_nodes.sh >> $WORKER

#OC cis 4.5
MASTER="kube_master_ocp_4_5.tmpl"
WORKER="kube_worker_ocp_4_5.tmpl"
echo "==> generate $MASTER and $WORKER"

cat ocp/helper_ocp.sh > $MASTER
cat ocp/4.5/enforcer/master/1_control_plane_components.sh >> $MASTER
cat ocp/4.5/enforcer/master/2_etcd.sh >> $MASTER
cat ocp/4.5/enforcer/master/3_control_plane_configuration.sh >> $MASTER
cat ocp/4.5/enforcer/master/5_policies.sh >> $MASTER
echo  "exit 0;" >> $MASTER

cat ocp/helper_ocp.sh > $WORKER
cat ocp/4.5/enforcer//worker/4_worker_nodes.sh >> $WORKER


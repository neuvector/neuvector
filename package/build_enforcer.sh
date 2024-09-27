#!/bin/bash
set -e

STAGE_DIR=stage

machine=$(uname -m)
echo "Machine hardware architecture is \"$machine\""

if [ "$machine" == "x86_64" ]; then
    echo "==> Unitest"
    go test github.com/neuvector/neuvector/...
fi

echo "==> Making dp"
cd monitor; make || exit $?; cd ..
if [ "$machine" == "aarch64" ]; then
    cd dp; make -f Makefile_arm64 || exit $?; cd ..
elif [ "$machine" == "x86_64" ]; then
    cd dp; make || exit $?; cd ..
fi
echo "==> Making monitor"
make -C monitor/
echo "==> Making nstools"
make -C tools/nstools/
echo "==> Making agent"
make -C agent/
echo "==> Making pathWalker"
make -C agent/workerlet/pathWalker

mkdir -p ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
mkdir -p ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
mkdir -p ${STAGE_DIR}/usr/local/bin/scripts/rem/
mkdir -p ${STAGE_DIR}/etc/
mkdir -p ${STAGE_DIR}/licenses
#
cp monitor/monitor ${STAGE_DIR}/usr/local/bin/
cp agent/agent ${STAGE_DIR}/usr/local/bin/
cp agent/workerlet/pathWalker/pathWalker ${STAGE_DIR}/usr/local/bin/
cp dp/dp ${STAGE_DIR}/usr/local/bin/
cp agent/nvbench/kube_runner.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/rh_runner.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/host.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/container.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/check_kube_version.sh ${STAGE_DIR}/usr/local/bin/scripts/
cp agent/nvbench/kube_master_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_worker_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_master_1_2_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_worker_1_2_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_master_1_4_1.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_worker_1_4_1.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_master_1_5_1.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_worker_1_5_1.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_master_1_6_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_worker_1_6_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_master_gke_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_worker_gke_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_master_ocp_4_3.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_worker_ocp_4_3.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_master_ocp_4_5.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kube_worker_ocp_4_5.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
cp agent/nvbench/kubecis_1_0_0.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
cp agent/nvbench/kubecis_1_2_0.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
cp agent/nvbench/kubecis_1_4_1.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
cp agent/nvbench/kubecis_1_5_1.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
cp agent/nvbench/kubecis_1_6_0.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
cp agent/nvbench/kubecis_gke_1_0_0.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
cp agent/nvbench/kubecis_ocp_4_5.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
cp agent/nvbench/kubecis_ocp_4_3.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
cp agent/nvbench/journal.tmpl ${STAGE_DIR}/usr/local/bin/scripts/
cp tools/nstools/nstools ${STAGE_DIR}/usr/local/bin/
cp -r agent/nvbench/utils/ ${STAGE_DIR}/usr/local/bin/scripts/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.6.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.23/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.24/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.8.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-k3s-1.8.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/gke-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/aks-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/eks-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/ocp/rh-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/

#
cp scripts/sysctl.conf ${STAGE_DIR}/etc/
cp scripts/configure.sh ${STAGE_DIR}/usr/local/bin/scripts/
cp scripts/teardown.sh ${STAGE_DIR}/usr/local/bin/scripts/
cp scripts/runtime-gdb.py ${STAGE_DIR}/usr/local/bin/scripts/

cd vendor && ../genlic.sh > ../${STAGE_DIR}/licenses/neuvector-license.txt
cd ..
cd dp && ../genlic.sh >> ../${STAGE_DIR}/licenses/neuvector-license.txt
cd ..

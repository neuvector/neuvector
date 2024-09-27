#!/bin/bash
set -e

STAGE_DIR=stage

machine=$(uname -m)
echo "Machine hardware architecture is \"$machine\""

if [ "$machine" == "x86_64" ]; then
    echo "==> Unitest"
    go test github.com/neuvector/neuvector/...
fi

echo "==> Making monitor"
make -C monitor
echo "==> Making nstools"
make -C tools/nstools/
if [ "$machine" == "x86_64" ]; then
	CONTROLLER_FILE="controller/controller-amd64"
else
	CONTROLLER_FILE="controller/controller-arm64"
fi
if [ -f "$CONTROLLER_FILE" ];then
	cp "$CONTROLLER_FILE" controller/controller
	chmod +x controller/controller
else 
	echo "==> Making controller"
	make -C controller/
fi
echo "==> Making upgrader"
make -C upgrader/

mkdir -p ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
mkdir -p ${STAGE_DIR}/etc/
mkdir -p ${STAGE_DIR}/etc/neuvector/templates
mkdir -p ${STAGE_DIR}/licenses
#
cp monitor/monitor ${STAGE_DIR}/usr/local/bin/
cp controller/controller ${STAGE_DIR}/usr/local/bin/
cp upgrader/upgrader ${STAGE_DIR}/usr/local/bin/
cp tools/nstools/nstools ${STAGE_DIR}/usr/local/bin/
#
cp scripts/sysctl.conf ${STAGE_DIR}/etc/
cp scripts/teardown.sh ${STAGE_DIR}/usr/local/bin/scripts/
cp scripts/runtime-gdb.py ${STAGE_DIR}/usr/local/bin/scripts/
#
cp templates/podTemplate.json ${STAGE_DIR}/etc/neuvector/templates/podTemplate.json
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.6.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.23/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.24/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.8.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-k3s-1.8.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/gke-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/aks-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/eks-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/ocp/rh-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cd vendor && ../genlic.sh > ../${STAGE_DIR}/licenses/neuvector-license.txt
cd ..

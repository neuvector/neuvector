.PHONY: fleet

REPO_URL = 10.1.127.3:5000
REPO_REL_URL = 10.1.127.12:5000
STAGE_DIR = stage
S_DATA_FILE = ubistage.tgz

copy_upd:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/neuvector/db
	#
	cp neuvector/upgrader/upgrader ${STAGE_DIR}/usr/local/bin/
	cp neuvector/data/cvedb.compact ${STAGE_DIR}/etc/neuvector/db/cvedb.compact
	cp neuvector/data/cvedb.regular ${STAGE_DIR}/etc/neuvector/db/cvedb.regular

copy_scan:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/neuvector/db
	#
	cp neuvector/monitor/monitor ${STAGE_DIR}/usr/local/bin/
	cp neuvector/scanner/scanner ${STAGE_DIR}/usr/local/bin/
	cp neuvector/scanner/task/scannerTask ${STAGE_DIR}/usr/local/bin/
	cp neuvector/scanner/rpmparser/rpmparser ${STAGE_DIR}/usr/local/bin/
	cp neuvector/data/cvedb.regular ${STAGE_DIR}/etc/neuvector/db/cvedb

copy_ctrl:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/
	#
	cp neuvector/monitor/monitor ${STAGE_DIR}/usr/local/bin/
	cp neuvector/controller/controller ${STAGE_DIR}/usr/local/bin/
	cp neuvector/tools/nstools/nstools ${STAGE_DIR}/usr/local/bin/
	cp neuvector/tools/sidekick/sidekick ${STAGE_DIR}/usr/local/bin/
	#
	cp neuvector/scripts/sysctl.conf ${STAGE_DIR}/etc/
	cp neuvector/scripts/teardown.sh ${STAGE_DIR}/usr/local/bin/
	cp neuvector/scripts/runtime-gdb.py ${STAGE_DIR}/usr/local/bin/

copy_enf:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/
	#
	cp neuvector/monitor/monitor ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/agent ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/workerlet/pathWalker/pathWalker ${STAGE_DIR}/usr/local/bin/
	cp neuvector/scanner/rpmparser/rpmparser ${STAGE_DIR}/usr/local/bin/
	cp neuvector/dp/dp ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/host.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/container.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/check_kube_version.sh ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_master_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_worker_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_master_1_2_0.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_worker_1_2_0.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_master_1_4_1.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_worker_1_4_1.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_master_1_5_1.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_worker_1_5_1.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_master_1_6_0.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_worker_1_6_0.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_master_gke_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_worker_gke_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_master_ocp_4_3.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_worker_ocp_4_3.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_master_ocp_4_5.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_worker_ocp_4_5.tmpl ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kubecis_1_0_0.rem ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kubecis_1_2_0.rem ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kubecis_1_4_1.rem ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kubecis_1_5_1.rem ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kubecis_1_6_0.rem ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kubecis_gke_1_0_0.rem ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kubecis_ocp_4_5.rem ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kubecis_ocp_4_3.rem ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/tools/host_package.sh ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/tools/container_package.sh ${STAGE_DIR}/usr/local/bin/
	cp neuvector/tools/nstools/nstools ${STAGE_DIR}/usr/local/bin/
	cp neuvector/tools/sidekick/sidekick ${STAGE_DIR}/usr/local/bin/
	#
	cp neuvector/scripts/sysctl.conf ${STAGE_DIR}/etc/
	cp neuvector/scripts/configure.sh ${STAGE_DIR}/usr/local/bin/
	cp neuvector/scripts/teardown.sh ${STAGE_DIR}/usr/local/bin/
	cp neuvector/scripts/runtime-gdb.py ${STAGE_DIR}/usr/local/bin/

copy_dp:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/
	#
	cp neuvector/dp/dp ${STAGE_DIR}/usr/local/bin/

copy_mgr:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/licenses/
	mkdir -p ${STAGE_DIR}/usr/lib/jvm/java-11-openjdk/lib/security/
	#
	cp manager/licenses/* ${STAGE_DIR}/licenses/
	#
	cp manager/cli/cli ${STAGE_DIR}/usr/local/bin/
	cp -r manager/cli/prog ${STAGE_DIR}/usr/local/bin/
	cp manager/scripts/* ${STAGE_DIR}/usr/local/bin/
	cp manager/java.security ${STAGE_DIR}/usr/lib/jvm/java-11-openjdk/lib/security/java.security
	cp manager/admin/target/scala-2.11/admin-assembly-1.0.jar ${STAGE_DIR}/usr/local/bin/

stage_init:
	rm -rf ${STAGE_DIR}; mkdir -p ${STAGE_DIR}
	#
	mkdir -p ${STAGE_DIR}/licenses/
	cd neuvector/vendor && ../genlic.sh > ../../${STAGE_DIR}/licenses/neuvector-license.txt
	cd ../..
	cd neuvector/dp && ../genlic.sh >> ../../${STAGE_DIR}/licenses/neuvector-license.txt
	cd ../..

stage_upd: stage_init copy_upd

stage_scan: stage_init copy_scan

stage_ctrl: stage_init copy_ctrl

stage_enf: stage_init copy_enf

stage_ctrlenf: stage_init copy_ctrl copy_enf

stage_all: stage_init copy_ctrl copy_enf copy_mgr
	mkdir -p ${STAGE_DIR}/etc/supervisor/conf.d
	cp neuvector/build/supervisord.all.conf ${STAGE_DIR}/etc/supervisor/conf.d/supervisord.conf

pull_fleet_base:
	docker pull $(REPO_REL_URL)/neuvector/fleet_base:latest
	docker pull $(REPO_REL_URL)/neuvector/controller_base:latest
	docker pull $(REPO_REL_URL)/neuvector/enforcer_base:latest

pull_all_base:
	docker pull $(REPO_REL_URL)/neuvector/all_base:jdk11



api_image:
	docker build -t neuvector/api -f neuvector/build/Dockerfile.api .

ctrl_image: pull_fleet_base stage_ctrl
	docker build --build-arg NV_TAG=$(NV_TAG) -t neuvector/controller:public -f neuvector/build/Dockerfile.controller .
	docker build -t neuvector/controller -f neuvector/build/Dockerfile.controller .

enf_image: pull_fleet_base stage_enf
	docker build --build-arg NV_TAG=$(NV_TAG) -t neuvector/enforcer -f neuvector/build/Dockerfile.enforcer .

ctrlenf_image: pull_fleet_base stage_ctrlenf
	docker build -t neuvector/ctrlenf:public -f neuvector/build/Dockerfile.ctrlenf.nolic .
	docker build -t neuvector/ctrlenf -f neuvector/build/Dockerfile.ctrlenf .

updater_image: pull_fleet_base stage_upd
	docker build -t neuvector/updater -f neuvector/build/Dockerfile.updater .

scanner_image: pull_fleet_base stage_scan
	docker build -t neuvector/scanner -f neuvector/build/Dockerfile.scanner .

all_image: pull_all_base stage_all
	docker build --build-arg NV_TAG=$(NV_TAG) -t neuvector/allinone:public -f neuvector/build/Dockerfile.all.nolic .
	docker build -t neuvector/allinone -f neuvector/build/Dockerfile.all .

ubi_scanner:
	rm -rf ${STAGE_DIR}; mkdir -p ${STAGE_DIR}
	mkdir -p ${STAGE_DIR}/licenses/
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/neuvector/certs/
	mkdir -p ${STAGE_DIR}/etc/neuvector/certs/internal/
	mkdir -p ${STAGE_DIR}/etc/neuvector/db/
	docker run -itd --name cache --entrypoint true ${REPO_URL}/neuvector/scanner:latest
	docker cp cache:/licenses/. ${STAGE_DIR}/licenses/
	docker cp cache:/etc/neuvector/certs/internal/. ${STAGE_DIR}/etc/neuvector/certs/internal/
	docker cp cache:/usr/local/bin/. ${STAGE_DIR}/usr/local/bin/
	docker cp cache:/etc/neuvector/db/cvedb ${STAGE_DIR}/etc/neuvector/db/cvedb
	docker stop cache; docker rm cache
	rm -f ${S_DATA_FILE} || true
	cd stage; tar -czvf ../${S_DATA_FILE} *; cd ..
	docker build --build-arg DATA_FILE=${S_DATA_FILE} -t neuvector/scanner.ubi -f neuvector/build/Dockerfile.scanner.ubi .


fleet:
	# This is running in neuvector/
	@echo "Making $@ ..."
	@docker pull $(REPO_REL_URL)/neuvector/build
	@docker run --rm -ia STDOUT --name build -e NV_BUILD_TARGET=$(NV_BUILD_TARGET) --net=none -v $(CURDIR):/go/src/github.com/neuvector/neuvector $(REPO_REL_URL)/neuvector/build $@

db:
	# This is running in neuvector/
	@echo "Making $@ ..."
	@docker pull $(REPO_REL_URL)/neuvector/build
	@docker run --rm -ia STDOUT --name build -e VULN_VER=$(VULN_VER) -v $(CURDIR):/go/src/github.com/neuvector/neuvector $(REPO_REL_URL)/neuvector/build $@

# Legacy Makefile.  Keep for backward compatibility
.PHONY: fleet

STAGE_DIR = stage
BASE_IMAGE_TAG = latest
BUILD_IMAGE_TAG = v3

copy_ctrl:
	mkdir -p ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	mkdir -p ${STAGE_DIR}/etc/
	mkdir -p ${STAGE_DIR}/etc/neuvector/templates
	#
	cp neuvector/monitor/monitor ${STAGE_DIR}/usr/local/bin/
	cp neuvector/controller/controller ${STAGE_DIR}/usr/local/bin/
	cp neuvector/upgrader/upgrader ${STAGE_DIR}/usr/local/bin/
	cp neuvector/tools/nstools/nstools ${STAGE_DIR}/usr/local/bin/
	#
	cp neuvector/scripts/sysctl.conf ${STAGE_DIR}/etc/
	cp neuvector/scripts/teardown.sh ${STAGE_DIR}/usr/local/bin/scripts/
	cp neuvector/scripts/runtime-gdb.py ${STAGE_DIR}/usr/local/bin/scripts/
	#
	cp neuvector/templates/podTemplate.json ${STAGE_DIR}/etc/neuvector/templates/podTemplate.json
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/cis-1.6.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/cis-1.23/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/cis-1.24/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/cis-1.8.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/cis-k3s-1.8.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/gke-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/aks-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/eks-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/ocp/rh-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/

copy_enf:
	mkdir -p ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	mkdir -p ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	mkdir -p ${STAGE_DIR}/usr/local/bin/scripts/rem/
	mkdir -p ${STAGE_DIR}/etc/
	#
	cp neuvector/monitor/monitor ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/agent ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/workerlet/pathWalker/pathWalker ${STAGE_DIR}/usr/local/bin/
	cp neuvector/dp/dp ${STAGE_DIR}/usr/local/bin/
	cp neuvector/agent/nvbench/kube_runner.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/rh_runner.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/host.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/container.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/check_kube_version.sh ${STAGE_DIR}/usr/local/bin/scripts/
	cp neuvector/agent/nvbench/kube_master_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_worker_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_master_1_2_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_worker_1_2_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_master_1_4_1.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_worker_1_4_1.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_master_1_5_1.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_worker_1_5_1.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_master_1_6_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_worker_1_6_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_master_gke_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_worker_gke_1_0_0.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_master_ocp_4_3.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_worker_ocp_4_3.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_master_ocp_4_5.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kube_worker_ocp_4_5.tmpl ${STAGE_DIR}/usr/local/bin/scripts/tmpl/
	cp neuvector/agent/nvbench/kubecis_1_0_0.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
	cp neuvector/agent/nvbench/kubecis_1_2_0.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
	cp neuvector/agent/nvbench/kubecis_1_4_1.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
	cp neuvector/agent/nvbench/kubecis_1_5_1.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
	cp neuvector/agent/nvbench/kubecis_1_6_0.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
	cp neuvector/agent/nvbench/kubecis_gke_1_0_0.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
	cp neuvector/agent/nvbench/kubecis_ocp_4_5.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
	cp neuvector/agent/nvbench/kubecis_ocp_4_3.rem ${STAGE_DIR}/usr/local/bin/scripts/rem/
	cp neuvector/agent/nvbench/journal.tmpl ${STAGE_DIR}/usr/local/bin/scripts/
	cp neuvector/tools/nstools/nstools ${STAGE_DIR}/usr/local/bin/
	cp -r neuvector/agent/nvbench/utils/ ${STAGE_DIR}/usr/local/bin/scripts/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/cis-1.6.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/cis-1.23/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/cis-1.24/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/cis-1.8.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/cis-k3s-1.8.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/gke-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/aks-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/kubernetes-cis-benchmark/eks-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
	cp -r neuvector/agent/nvbench/ocp/rh-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/

	#
	cp neuvector/scripts/sysctl.conf ${STAGE_DIR}/etc/
	cp neuvector/scripts/configure.sh ${STAGE_DIR}/usr/local/bin/scripts/
	cp neuvector/scripts/teardown.sh ${STAGE_DIR}/usr/local/bin/scripts/
	cp neuvector/scripts/runtime-gdb.py ${STAGE_DIR}/usr/local/bin/scripts/

copy_dp:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/
	#
	cp neuvector/dp/dp ${STAGE_DIR}/usr/local/bin/

copy_mgr:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/licenses/
	mkdir -p ${STAGE_DIR}/usr/lib/jvm/java-17-openjdk/lib/security/
	#
	cp manager/licenses/* ${STAGE_DIR}/licenses/
	#
	cp manager/cli/cli ${STAGE_DIR}/usr/local/bin/
	cp manager/cli/cli.py ${STAGE_DIR}/usr/local/bin/
	cp -r manager/cli/prog ${STAGE_DIR}/usr/local/bin/
	cp manager/scripts/* ${STAGE_DIR}/usr/local/bin/
	cp manager/java.security ${STAGE_DIR}/usr/lib/jvm/java-17-openjdk/lib/security/java.security
	cp manager/admin/target/scala-3.3.4/admin-assembly-1.0.jar ${STAGE_DIR}/usr/local/bin/

stage_init:
	rm -rf ${STAGE_DIR}; mkdir -p ${STAGE_DIR}
	#
	mkdir -p ${STAGE_DIR}/licenses/
	cd neuvector/vendor && ../genlic.sh > ../../${STAGE_DIR}/licenses/neuvector-license.txt
	cd ../..
	cd neuvector/dp && ../genlic.sh >> ../../${STAGE_DIR}/licenses/neuvector-license.txt
	cd ../..

stage_scan: stage_init copy_scan

stage_ctrl: stage_init copy_ctrl

stage_enf: stage_init copy_enf

stage_all: stage_init copy_ctrl copy_enf copy_mgr
	mkdir -p ${STAGE_DIR}/etc/supervisor/conf.d
	cp neuvector/build/supervisord.all.conf ${STAGE_DIR}/etc/supervisor/conf.d/supervisord.conf

pull_fleet_base:
	docker pull neuvector/controller_base:${BASE_IMAGE_TAG}
	docker pull neuvector/enforcer_base:${BASE_IMAGE_TAG}

pull_all_base:
	docker pull neuvector/all_base:${BASE_IMAGE_TAG}


api_image:
	docker build -t neuvector/api -f neuvector/build/Dockerfile.api .

ctrl_image: pull_fleet_base stage_ctrl
	docker build --build-arg NV_TAG=$(NV_TAG) --build-arg BASE_IMAGE_TAG=${BASE_IMAGE_TAG} -t neuvector/controller -f neuvector/build/Dockerfile.controller .

enf_image: pull_fleet_base stage_enf
	docker build --build-arg NV_TAG=$(NV_TAG) --build-arg BASE_IMAGE_TAG=${BASE_IMAGE_TAG} -t neuvector/enforcer -f neuvector/build/Dockerfile.enforcer .

all_image: pull_all_base stage_all
	docker build --build-arg NV_TAG=$(NV_TAG) --build-arg BASE_IMAGE_TAG=${BASE_IMAGE_TAG} -t neuvector/allinone -f neuvector/build/Dockerfile.all .

fleet:
	# This is running in neuvector/
	@echo "Making $@ ..."
	@docker pull neuvector/build_fleet:${BUILD_IMAGE_TAG}
	@docker run --rm -ia STDOUT --name build -e NV_BUILD_TARGET=$(NV_BUILD_TARGET) --net=none -v $(CURDIR):/go/src/github.com/neuvector/neuvector -w /go/src/github.com/neuvector/neuvector --entrypoint ./make_fleet.sh neuvector/build_fleet:${BUILD_IMAGE_TAG}

# Newer Makefile

RUNNER := docker
IMAGE_BUILDER := $(RUNNER) buildx
MACHINE := neuvector
BUILDX_ARGS ?= --sbom=true --attest type=provenance,mode=max --cache-to type=gha --cache-from type=gha
DEFAULT_PLATFORMS := linux/amd64,linux/arm64,linux/x390s,linux/riscv64

COMMIT = $(shell git rev-parse --short HEAD)
ifeq ($(VERSION),)
	# Define VERSION, which is used for image tags or to bake it into the
	# compiled binary to enable the printing of the application version, 
	# via the --version flag.
	CHANGES = $(shell git status --porcelain --untracked-files=no)
	ifneq ($(CHANGES),)
		DIRTY = -dirty
	endif

	COMMIT = $(shell git rev-parse --short HEAD)
	VERSION = $(COMMIT)$(DIRTY)

	GIT_TAG = $(shell git tag -l --contains HEAD | head -n 1)

	# Override VERSION with the Git tag if the current HEAD has a tag pointing to
	# it AND the worktree isn't dirty.
	ifneq ($(GIT_TAG),)
		ifeq ($(DIRTY),)
			VERSION = $(GIT_TAG)
		endif
	endif
endif

ifeq ($(TAG),)
	TAG = $(VERSION)
	ifneq ($(DIRTY),)
		TAG = dev
	endif
endif

TARGET_PLATFORMS ?= linux/amd64,linux/arm64
REPO ?= neuvector
CONTROLLER_IMAGE = $(REPO)/controller:$(TAG)
ENFORCER_IMAGE = $(REPO)/enforcer:$(TAG)
BUILD_ACTION = --load

buildx-machine:
	docker buildx ls
	@docker buildx ls | grep $(MACHINE) || \
	docker buildx create --name=$(MACHINE) --platform=$(DEFAULT_PLATFORMS)

test-controller-image:
	# Instead of loading image, target all platforms, effectivelly testing
	# the build for the target architectures.
	$(MAKE) build-controller-image BUILD_ACTION="--platform=$(TARGET_PLATFORMS)"

build-controller-image: buildx-machine ## build (and load) the container image targeting the current platform.
	$(IMAGE_BUILDER) build -f package/Dockerfile.controller \
		--builder $(MACHINE) $(IMAGE_ARGS) \
		--build-arg VERSION=$(VERSION) -t "$(CONTROLLER_IMAGE)" $(BUILD_ACTION) .
	@echo "Built $(CONTROLLER_IMAGE)"

push-controller-image: buildx-machine
	$(IMAGE_BUILDER) build -f package/Dockerfile.controller \
		--builder $(MACHINE) $(IMAGE_ARGS) $(IID_FILE_FLAG) $(BUILDX_ARGS) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --platform=$(TARGET_PLATFORMS) -t "$(REPO)/$(IMAGE_PREFIX)controller:$(TAG)" --push .
	@echo "Pushed $(REPO)/$(IMAGE_PREFIX)controller:$(TAG)"

test-enforcer-image:
	# Instead of loading image, target all platforms, effectivelly testing
	# the build for the target architectures.
	$(MAKE) build-enforcer-image BUILD_ACTION="--platform=$(TARGET_PLATFORMS)"

build-enforcer-image: buildx-machine ## build (and load) the container image targeting the current platform.
	$(IMAGE_BUILDER) build -f package/Dockerfile.enforcer \
		--builder $(MACHINE) $(IMAGE_ARGS) \
		--build-arg VERSION=$(VERSION) -t "$(ENFORCER_IMAGE)" $(BUILD_ACTION) .
	@echo "Built $(ENFORCER_IMAGE)"

push-enforcer-image: buildx-machine
	$(IMAGE_BUILDER) build -f package/Dockerfile.enforcer \
		--builder $(MACHINE) $(IMAGE_ARGS) $(IID_FILE_FLAG) $(BUILDX_ARGS) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --platform=$(TARGET_PLATFORMS) -t "$(REPO)/$(IMAGE_PREFIX)enforcer:$(TAG)" --push .
	@echo "Pushed $(REPO)/$(IMAGE_PREFIX)enforcer:$(TAG)"

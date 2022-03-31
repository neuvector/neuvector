REPO_URL = 10.1.127.3:5000
REPO_REL_URL = 10.1.127.12:5000
STAGE_DIR = stage
SHORT_VER = $(subst .,,$(RELEASE))
C_DATA_FILE = c$(SHORT_VER)stage.tgz
E_DATA_FILE = e$(SHORT_VER)stage.tgz
M_DATA_FILE = m$(SHORT_VER)stage.tgz
S_DATA_FILE = s$(SHORT_VER)stage.tgz

stage_init:
	rm -rf ${STAGE_DIR}; mkdir -p ${STAGE_DIR}
	mkdir -p ${STAGE_DIR}/licenses/
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/neuvector/certs/
	mkdir -p ${STAGE_DIR}/etc/neuvector/certs/internal/

bci_controller: stage_init
	docker run -itd --name cache --entrypoint true ${REPO_URL}/neuvector/controller:${RELEASE}
	docker cp cache:/licenses/. ${STAGE_DIR}/licenses/
	docker cp cache:/etc/neuvector/certs/internal/. ${STAGE_DIR}/etc/neuvector/certs/internal/
	docker cp cache:/etc/neuvector/certs/. ${STAGE_DIR}/etc/neuvector/certs/
	docker cp cache:/usr/local/bin/. ${STAGE_DIR}/usr/local/bin/
	docker cp cache:/etc/sysctl.conf ${STAGE_DIR}/etc/
	docker stop cache; docker rm cache
	rm -f ${C_DATA_FILE} || true
	cd stage; tar -czvf ../${C_DATA_FILE} *; cd ..
	docker build --build-arg RELEASE=${RELEASE} --build-arg DATA_FILE=${C_DATA_FILE} -t neuvector/controller.bci:$(RELEASE) -f Dockerfile.controller .

bci_enforcer: stage_init
	docker run -itd --name cache --entrypoint true ${REPO_URL}/neuvector/enforcer:${RELEASE}
	docker cp cache:/licenses/. ${STAGE_DIR}/licenses/
	docker cp cache:/etc/neuvector/certs/internal/. ${STAGE_DIR}/etc/neuvector/certs/internal/
	docker cp cache:/etc/neuvector/certs/. ${STAGE_DIR}/etc/neuvector/certs/
	docker cp cache:/usr/local/bin/. ${STAGE_DIR}/usr/local/bin/
	docker cp cache:/etc/sysctl.conf ${STAGE_DIR}/etc/
	docker stop cache; docker rm cache
	rm -f ${E_DATA_FILE} || true
	cd stage; tar -czvf ../${E_DATA_FILE} *; cd ..
	docker build --build-arg RELEASE=${RELEASE} --build-arg DATA_FILE=${E_DATA_FILE} -t neuvector/enforcer.bci:$(RELEASE) -f Dockerfile.enforcer .

bci_manager: stage_init
	mkdir -p ${STAGE_DIR}/usr/lib/jvm/java-11-openjdk/lib/security/
	docker run -itd --name cache --entrypoint true ${REPO_URL}/neuvector/manager:${RELEASE}
	docker cp cache:/licenses/. ${STAGE_DIR}/licenses/
	docker cp cache:/etc/neuvector/certs/. ${STAGE_DIR}/etc/neuvector/certs/
	docker cp cache:/usr/local/bin/. ${STAGE_DIR}/usr/local/bin/
	docker cp cache:/usr/lib/jvm/java-11-openjdk/lib/security/java.security ${STAGE_DIR}/usr/lib/jvm/java-11-openjdk/lib/security/java.security
	docker stop cache; docker rm cache
	rm -rf ${STAGE_DIR}/usr/local/bin/support
	rm -rf ${STAGE_DIR}/usr/local/bin/cli
	rm -rf ${STAGE_DIR}/usr/local/bin/prog
	rm -f ${M_DATA_FILE} || true
	cd stage; tar -czvf ../${M_DATA_FILE} *; cd ..
	docker build --build-arg RELEASE=${RELEASE} --build-arg DATA_FILE=${M_DATA_FILE} -t neuvector/manager.bci:$(RELEASE) -f Dockerfile.manager .
	
bci_scanner: stage_init
	mkdir -p ${STAGE_DIR}/etc/neuvector/db/
	docker run -itd --name cache --entrypoint true ${REPO_URL}/neuvector/scanner:latest
	docker cp cache:/licenses/. ${STAGE_DIR}/licenses/
	docker cp cache:/etc/neuvector/certs/internal/. ${STAGE_DIR}/etc/neuvector/certs/internal/
	docker cp cache:/usr/local/bin/. ${STAGE_DIR}/usr/local/bin/
	docker cp cache:/etc/neuvector/db/cvedb ${STAGE_DIR}/etc/neuvector/db/cvedb
	docker stop cache; docker rm cache
	rm -f ${S_DATA_FILE} || true
	cd stage; tar -czvf ../${S_DATA_FILE} *; cd ..
	docker build --no-cache --build-arg RELEASE=${RELEASE} --build-arg DATA_FILE=${S_DATA_FILE} -t neuvector/scanner.bci:$(RELEASE) -f Dockerfile.scanner .

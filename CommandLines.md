## Use build container to make binaries
In neuvector/ directory
```
make fleet
```

## To make container image
In neuvector/ parent directory
```
cp neuvector/Makefile .
make ctrl_image
make enf_image
```

### Both Controller and Enforcer
CTRL_PATH_DEBUG
> Enable control path debug. Default ```0```

### Controller
DISABLE_PACKET_CAPTURE
> Disable packet capture 

CTRL_PERSIST_CONFIG
> Enable save and restore persisted configuratons.

FED_SERVER_PORT
> Federation master server port

### Enforcer
NV_PLATFORM_INFO
> Allow user to special container port information
> 
> E.g. NV_PLATFORM_INFO=platform=tuniu;if-eth0=global
> 
> E.g. NV_PLATFORM_INFO=platform=Docker -- bypass the container-based platform detection
> 
> E.g. NV_PLATFORM_INFO=platform=Kubernetes:GKE -- specify platform and flavor at the same time

CONTAINER_NET_TYPE
> Options are 'default' and 'macvlan'

NV_SYSTEM_GROUPS
> Specify the services that match the filters as system contaienr. Only for docker platform (NVSHAS-4394)
> NV_SYSTEM_GROUPS=ucp-*;node

### Scanner
SCANNER_DOCKER_URL
> Special the docker socket. Used to scan images that are not in the registry. Eg. unix:///var/run/docker.sock, tcp://10.1.2.3:2376

### Manager
MANAGER_SSL
> Expose HTTP instead of HTTPS for client connection.
> MANAGER_SSL=off

## Docker run

### Controller

`docker run -itd --privileged --name neuvector.controller -e CLUSTER_JOIN_ADDR=$controller_ip -p 18301:18301 -p 18301:18301/udp -p 18300:18300 -p 18400:18400 -p 10443:10443 -v /var/neuvector:/var/neuvector -v /var/run/docker.sock:/var/run/docker.sock -v /proc:/host/proc:ro -v /sys/fs/cgroup/:/host/cgroup/:ro neuvector/controller
`

### Enforcer

`docker run -itd --privileged --name neuvector.enforcer -e CLUSTER_JOIN_ADDR=$controller_ip --pid=host -p 18301:18301 -p 18301:18301/udp -p 18401:18401 -v /var/neuvector:/var/neuvector -v /var/run/docker.sock:/var/run/docker.sock -v /proc:/host/proc:ro -v /sys/fs/cgroup/:/host/cgroup/:ro neuvector/enforcer
`

### Manager

`docker run -itd --name neuvector.manager -e CTRL_SERVER_IP=$controller_ip  -p 8443:8443 neuvector/manager
`

### Scanner

`docker run --name neuvector.scanner --rm -e CLUSTER_JOIN_ADDR=$controller_ip neuvector/scanner
`

### Scanner Standalone

`docker run --name neuvector.scanner --rm -e SCANNER_REPOSITORY=ubuntu -e SCANNER_TAG=16.04 -e -v /var/run/docker.sock:/var/run/docker.sock -v /var/neuvector:/var/neuvector  neuvector/scanner
`

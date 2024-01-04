module github.com/neuvector/neuvector

go 1.14

replace (
	github.com/containerd/containerd => github.com/containerd/containerd v1.3.10
	github.com/containerd/cri => github.com/containerd/cri v1.19.0
	github.com/cri-o/cri-o => github.com/cri-o/cri-o v1.15.4
	github.com/docker/distribution => github.com/docker/distribution v2.8.0-beta.1+incompatible
	github.com/docker/docker => github.com/docker/docker v1.13.1
	github.com/golang/protobuf => github.com/golang/protobuf v1.3.3
	github.com/kubernetes/cri-api => k8s.io/cri-api v0.22.3
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.0-rc5
	github.com/russellhaering/gosaml2 => github.com/holyspectral/gosaml2 v0.0.0-20231003195827-3d916621a704
	golang.org/x/net => golang.org/x/net v0.0.0-20200822124328-c89045814202
	google.golang.org/genproto => google.golang.org/genproto v0.0.0-20190819201941-24fa4b261c55
	google.golang.org/grpc => google.golang.org/grpc v1.30.1
	k8s.io/api => k8s.io/api v0.21.14
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.21.14
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.0
	k8s.io/apiserver => k8s.io/apiserver v0.20.15
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.20.15
	k8s.io/client-go => k8s.io/client-go v0.20.15
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.20.15
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.20.15
	k8s.io/code-generator => k8s.io/code-generator v0.20.15
	k8s.io/component-base => k8s.io/component-base v0.20.15
	k8s.io/component-helpers => k8s.io/component-helpers v0.20.15
	k8s.io/controller-manager => k8s.io/controller-manager v0.20.15
	k8s.io/cri-api => k8s.io/cri-api v0.20.15
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.20.15
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.20.15
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.20.15
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.20.15
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.20.15
	k8s.io/kubectl => k8s.io/kubectl v0.20.15
	k8s.io/kubelet => k8s.io/kubelet v0.20.15
	k8s.io/kubernetes => k8s.io/kubernetes v1.23.1
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.20.15
	k8s.io/metrics => k8s.io/metrics v0.20.15
	k8s.io/mount-utils => k8s.io/mount-utils v0.20.14
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.22.5
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.20.15
)

require (
	github.com/aws/aws-sdk-go v1.42.22
	github.com/beevik/etree v1.2.0
	github.com/cenk/hub v1.0.1 // indirect
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20210604223624-c1acbc6ec984
	github.com/codeskyblue/go-sh v0.0.0-20200712050446-30169cf553fe
	github.com/containerd/containerd v1.4.11
	github.com/containerd/typeurl v1.0.2
	github.com/cri-o/cri-o v0.0.0-00010101000000-000000000000
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v20.10.7+incompatible
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.4.0
	github.com/doug-martin/goqu/v9 v9.19.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/glenn-brown/golang-pkg-pcre v0.0.0-20120522223659-48bb82a8b8ce
	github.com/gogo/googleapis v1.4.1 // indirect
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/uuid v1.3.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-version v1.4.0
	github.com/hashicorp/serf v0.9.7
	github.com/jonboulle/clockwork v0.3.0
	github.com/julienschmidt/httprouter v1.3.0
	github.com/knqyf263/go-rpmdb v0.0.0-20220209103220-0f7a6d951a6d
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.16
	github.com/mitchellh/mapstructure v1.4.3
	github.com/neuvector/k8s v1.2.1-0.20220214174348-d0b3f377461e
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/pquerna/cachecontrol v0.0.0-20171018203845-0dec1b30a021
	github.com/russellhaering/gosaml2 v0.9.1
	github.com/russellhaering/goxmldsig v1.4.0
	github.com/samalba/dockerclient v0.0.0-20160531175551-a30362618471
	github.com/sirupsen/logrus v1.8.1
	github.com/spaolacci/murmur3 v0.0.0-20180118202830-f09979ecbc72
	github.com/streadway/simpleuuid v0.0.0-20130420165545-6617b501e485
	github.com/stretchr/testify v1.7.1
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74
	golang.org/x/crypto v0.0.0-20220128200615-198e4374d7ed // indirect
	golang.org/x/net v0.0.0-20220722155237-a158d28d115b
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
	golang.org/x/sys v0.0.0-20220209214540-3681064d5158
	golang.org/x/tools v0.1.10 // indirect
	google.golang.org/grpc v1.40.0
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/square/go-jose.v2 v2.2.2
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	k8s.io/api v0.22.5
	k8s.io/apimachinery v0.25.2
	k8s.io/cri-api v0.0.0
	sigs.k8s.io/yaml v1.3.0
)

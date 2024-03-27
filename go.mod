module github.com/neuvector/neuvector

go 1.20

replace (
	github.com/containerd/containerd => github.com/containerd/containerd v1.3.10
	github.com/containerd/cri => github.com/containerd/cri v1.19.0
	github.com/cri-o/cri-o => github.com/cri-o/cri-o v1.15.4
	github.com/docker/distribution => github.com/docker/distribution v2.8.0-beta.1+incompatible
	github.com/docker/docker => github.com/docker/docker v1.13.1
	github.com/kubernetes/cri-api => k8s.io/cri-api v0.22.3
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.0-rc5
	github.com/russellhaering/gosaml2 => github.com/holyspectral/gosaml2 v0.0.0-20231003195827-3d916621a704
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
	github.com/cenkalti/rpc2 v0.0.0-20210604223624-c1acbc6ec984
	github.com/codeskyblue/go-sh v0.0.0-20200712050446-30169cf553fe
	github.com/containerd/containerd v1.4.11
	github.com/containerd/typeurl v1.0.2
	github.com/cri-o/cri-o v0.0.0-00010101000000-000000000000
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v20.10.7+incompatible
	github.com/docker/go-units v0.4.0
	github.com/doug-martin/goqu/v9 v9.19.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/glenn-brown/golang-pkg-pcre v0.0.0-20120522223659-48bb82a8b8ce
	github.com/golang/protobuf v1.5.4
	github.com/google/uuid v1.4.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-version v1.4.0
	github.com/hashicorp/serf v0.9.7
	github.com/jonboulle/clockwork v0.3.0
	github.com/julienschmidt/httprouter v1.3.0
	github.com/knqyf263/go-rpmdb v0.0.0-20220209103220-0f7a6d951a6d
	github.com/mattn/go-sqlite3 v1.14.16
	github.com/mitchellh/mapstructure v1.4.3
	github.com/neuvector/k8s v1.4.1-0.20240306034525-a5d3b887be81
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
	golang.org/x/net v0.22.0
	golang.org/x/oauth2 v0.14.0
	golang.org/x/sys v0.18.0
	google.golang.org/grpc v1.61.0
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/square/go-jose.v2 v2.2.2
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.22.5
	k8s.io/apimachinery v0.25.2
	k8s.io/cri-api v0.0.0
	sigs.k8s.io/yaml v1.3.0
)

require (
	github.com/Microsoft/go-winio v0.4.17 // indirect
	github.com/Microsoft/hcsshim v0.8.22 // indirect
	github.com/armon/go-metrics v0.0.0-20180917152333-f0300d1749da // indirect
	github.com/cenk/hub v1.0.1 // indirect
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/codegangsta/inject v0.0.0-20150114235600-33e0aa1cb7c0 // indirect
	github.com/containerd/cgroups v1.0.1 // indirect
	github.com/containerd/continuity v0.1.0 // indirect
	github.com/containerd/fifo v1.0.0 // indirect
	github.com/containerd/ttrpc v1.0.2 // indirect
	github.com/containers/storage v1.13.7 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/go-logr/logr v1.2.0 // indirect
	github.com/gogo/googleapis v1.4.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.0.0 // indirect
	github.com/hashicorp/golang-lru v0.5.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.11 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6 // indirect
	github.com/opencontainers/runc v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20200410134404-eec4a21b6bb0 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/klog/v2 v2.30.0 // indirect
	lukechampine.com/uint128 v1.1.1 // indirect
	modernc.org/cc/v3 v3.35.22 // indirect
	modernc.org/ccgo/v3 v3.15.1 // indirect
	modernc.org/libc v1.14.1 // indirect
	modernc.org/mathutil v1.4.1 // indirect
	modernc.org/memory v1.0.5 // indirect
	modernc.org/opt v0.1.1 // indirect
	modernc.org/sqlite v1.14.5 // indirect
	modernc.org/strutil v1.1.1 // indirect
	modernc.org/token v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
)

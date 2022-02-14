module github.com/neuvector/neuvector

go 1.14

replace (
	github.com/containerd/containerd => github.com/containerd/containerd v1.3.10
	github.com/containerd/cri => github.com/containerd/cri v1.19.0
	github.com/cri-o/cri-o => github.com/cri-o/cri-o v1.15.4
	github.com/docker/distribution => github.com/docker/distribution v2.8.0-beta.1+incompatible
	github.com/kubernetes/cri-api => k8s.io/cri-api v0.22.3
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.0-rc5
	golang.org/x/net => golang.org/x/net v0.0.0-20200822124328-c89045814202
	google.golang.org/grpc => google.golang.org/grpc v1.30.1
	k8s.io/api => k8s.io/api v0.18.19
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.18.19
	k8s.io/apimachinery => k8s.io/apimachinery v0.17.17
	k8s.io/apiserver => k8s.io/apiserver v0.18.19
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.18.19
	k8s.io/client-go => k8s.io/client-go v0.18.19
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.18.19
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.18.19
	k8s.io/code-generator => k8s.io/code-generator v0.18.19
	k8s.io/component-base => k8s.io/component-base v0.18.19
	k8s.io/component-helpers => k8s.io/component-helpers v0.20.14
	k8s.io/controller-manager => k8s.io/controller-manager v0.20.14
	k8s.io/cri-api => k8s.io/cri-api v0.18.19
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.18.19
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.18.19
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.18.19
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.18.19
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.18.19
	k8s.io/kubectl => k8s.io/kubectl v0.18.19
	k8s.io/kubelet => k8s.io/kubelet v0.18.19
	k8s.io/kubernetes => k8s.io/kubernetes v1.23.1
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.18.19
	k8s.io/metrics => k8s.io/metrics v0.18.19
	k8s.io/mount-utils => k8s.io/mount-utils v0.20.14
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.22.5
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.18.19
)

require (
	bitbucket.org/bertimus9/systemstat v0.0.0-20180207000608-0eeff89b0690 // indirect
	github.com/Azure/azure-sdk-for-go v55.0.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.18 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/GoogleCloudPlatform/k8s-cloud-provider v1.16.1-0.20210702024009-ea6160c1d0e3 // indirect
	github.com/JeffAshton/win_pdh v0.0.0-20161109143554-76bb4ee9f0ab // indirect
	github.com/Microsoft/hcsshim v0.8.22 // indirect
	github.com/RackSec/srslog v0.0.0-20180709174129-a4725f04ec91
	github.com/auth0/go-jwt-middleware v1.0.1 // indirect
	github.com/aws/aws-sdk-go v1.42.22
	github.com/beevik/etree v1.1.0
	github.com/boltdb/bolt v1.3.1 // indirect
	github.com/cenk/hub v1.0.1 // indirect
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20210604223624-c1acbc6ec984
	github.com/clusterhq/flocker-go v0.0.0-20160920122132-2b8b7259d313 // indirect
	github.com/codeskyblue/go-sh v0.0.0-20200712050446-30169cf553fe
	github.com/container-storage-interface/spec v1.5.0 // indirect
	github.com/containerd/containerd v1.4.11
	github.com/containerd/project v0.0.0-20190306185219-831961d1e0c8 // indirect
	github.com/containerd/typeurl v1.0.2
	github.com/containernetworking/cni v0.8.1 // indirect
	github.com/containers/buildah v1.11.4 // indirect
	github.com/containers/image/v5 v5.0.1-0.20200205124631-82291c45f2b0 // indirect
	github.com/containers/libpod v0.8.3-0.20191029195851-e7540d0406c4 // indirect
	github.com/containers/psgo v1.4.0 // indirect
	github.com/containers/storage v1.13.7 // indirect
	github.com/coredns/corefile-migration v1.0.14 // indirect
	github.com/cri-o/cri-o v0.0.0-00010101000000-000000000000
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v20.10.12+incompatible
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.4.0
	github.com/ericchiang/k8s v1.2.0 // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/fsnotify/fsnotify v1.4.9
	github.com/ghodss/yaml v1.0.0
	github.com/glenn-brown/golang-pkg-pcre v0.0.0-20120522223659-48bb82a8b8ce
	github.com/go-ozzo/ozzo-validation v3.5.0+incompatible // indirect
	github.com/go-zoo/bone v1.3.0 // indirect
	github.com/gogo/googleapis v1.4.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2
	github.com/golangci/golangci-lint v1.18.0 // indirect
	github.com/google/cadvisor v0.43.0 // indirect
	github.com/google/uuid v1.3.0
	github.com/googleapis/gnostic v0.5.5 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-version v1.4.0
	github.com/hashicorp/serf v0.9.7
	github.com/heketi/heketi v10.3.0+incompatible // indirect
	github.com/heketi/tests v0.0.0-20151005000721-f3775cbcefd6 // indirect
	github.com/ishidawataru/sctp v0.0.0-20190723014705-7c296d48a2b5 // indirect
	github.com/julienschmidt/httprouter v1.3.0
	github.com/kr/text v0.2.0 // indirect
	github.com/libopenstorage/openstorage v1.0.0 // indirect
	github.com/lpabon/godbc v0.1.1 // indirect
	github.com/mitchellh/mapstructure v1.4.3
	github.com/moby/ipvs v1.0.1 // indirect
	github.com/mohae/deepcopy v0.0.0-20170603005431-491d3605edfb // indirect
	github.com/mrunalp/fileutils v0.5.0 // indirect
	github.com/mvdan/xurls v1.1.0 // indirect
	github.com/neuvector/k8s v1.2.1-0.20220214174348-d0b3f377461e
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d
	github.com/onsi/ginkgo v1.14.0 // indirect
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/opencontainers/selinux v1.8.2 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20171018203845-0dec1b30a021
	github.com/prometheus/common v0.28.0 // indirect
	github.com/quobyte/api v0.1.8 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/russellhaering/goxmldsig v1.1.1
	github.com/samalba/dockerclient v0.0.0-20160531175551-a30362618471
	github.com/seccomp/containers-golang v0.3.1 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/spaolacci/murmur3 v0.0.0-20180118202830-f09979ecbc72
	github.com/spf13/cobra v1.2.1 // indirect
	github.com/storageos/go-api v2.2.0+incompatible // indirect
	github.com/streadway/simpleuuid v0.0.0-20130420165545-6617b501e485
	github.com/stretchr/testify v1.7.0
	github.com/vbatts/git-validation v1.0.0 // indirect
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74
	go.etcd.io/etcd/client/v3 v3.5.0 // indirect
	go.opentelemetry.io/otel/sdk v0.20.0 // indirect
	go.opentelemetry.io/proto/otlp v0.7.0 // indirect
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5 // indirect
	golang.org/x/exp v0.0.0-20210220032938-85be41e4509f // indirect
	golang.org/x/net v0.0.0-20211209124913-491a49abca63
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
	golang.org/x/sys v0.0.0-20210831042530-f4d43177bf5e
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac // indirect
	golang.org/x/tools v0.1.6-0.20210820212750-d4cc65f0b2ff // indirect
	gonum.org/v1/gonum v0.6.2 // indirect
	gonum.org/v1/netlib v0.0.0-20190331212654-76723241ea4e // indirect
	google.golang.org/genproto v0.0.0-20210831024726-fe130286e0e2 // indirect
	google.golang.org/grpc v1.40.0
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/square/go-jose.v2 v2.2.2
	k8s.io/api v0.22.5
	k8s.io/apiextensions-apiserver v0.0.0 // indirect
	k8s.io/apimachinery v0.22.5
	k8s.io/cluster-bootstrap v0.0.0 // indirect
	k8s.io/component-helpers v0.0.0 // indirect
	k8s.io/controller-manager v0.0.0 // indirect
	k8s.io/cri-api v0.0.0
	k8s.io/klog/v2 v2.30.0 // indirect
	k8s.io/kube-aggregator v0.0.0 // indirect
	k8s.io/kube-controller-manager v0.0.0 // indirect
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65 // indirect
	k8s.io/kube-proxy v0.0.0 // indirect
	k8s.io/kube-scheduler v0.0.0 // indirect
	k8s.io/kubectl v0.0.0 // indirect
	k8s.io/kubelet v0.0.0 // indirect
	k8s.io/legacy-cloud-providers v0.0.0 // indirect
	k8s.io/mount-utils v0.0.0 // indirect
	k8s.io/pod-security-admission v0.0.0 // indirect
	k8s.io/sample-apiserver v0.0.0 // indirect
	k8s.io/system-validators v1.6.0 // indirect
	k8s.io/utils v0.0.0-20210930125809-cb0fa318a74b // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.1.2 // indirect
)

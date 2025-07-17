module github.com/neuvector/neuvector

go 1.24.0

toolchain go1.24.5

replace (
	github.com/fsnotify/fsnotify => github.com/fsnotify/fsnotify v1.9.0
	k8s.io/cri-api => k8s.io/cri-api v0.25.16
)

require (
	github.com/Microsoft/hcsshim v0.13.0 // indirect
	github.com/aws/aws-sdk-go v1.55.7
	github.com/beevik/etree v1.5.1
	github.com/cenkalti/rpc2 v1.0.4
	github.com/codeskyblue/go-sh v0.0.0-20250509230738-c29da582b0f5
	github.com/containerd/containerd/api v1.9.0
	github.com/containerd/containerd/v2 v2.1.3
	github.com/containerd/typeurl/v2 v2.2.3
	github.com/docker/distribution v2.8.3+incompatible
	github.com/docker/docker v28.1.1+incompatible
	github.com/docker/go-units v0.5.0 // indirect
	github.com/doug-martin/goqu/v9 v9.19.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/glenn-brown/golang-pkg-pcre v0.0.0-20120522223659-48bb82a8b8ce
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/golang/protobuf v1.5.4
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-version v1.7.0
	github.com/imdario/mergo v0.3.10 // indirect
	github.com/jonboulle/clockwork v0.5.0
	github.com/jrhouston/k8slock v0.2.0
	github.com/julienschmidt/httprouter v1.3.0
	github.com/mattn/go-sqlite3 v1.14.28
	github.com/mitchellh/mapstructure v1.5.0
	github.com/neuvector/k8s v1.4.1-0.20240927235747-43bcf20a80a3
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/runtime-spec v1.2.1
	github.com/pquerna/cachecontrol v0.2.0
	github.com/russellhaering/gosaml2 v0.10.0
	github.com/russellhaering/goxmldsig v1.5.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spaolacci/murmur3 v1.1.0
	github.com/streadway/simpleuuid v0.0.0-20130420165545-6617b501e485
	github.com/stretchr/testify v1.10.0
	github.com/urfave/cli/v2 v2.27.7
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	golang.org/x/net v0.42.0
	golang.org/x/oauth2 v0.30.0
	golang.org/x/sys v0.34.0
	google.golang.org/grpc v1.73.0
	google.golang.org/grpc/security/advancedtls v1.0.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.32.3
	k8s.io/apiextensions-apiserver v0.29.3
	k8s.io/apimachinery v0.32.3
	k8s.io/client-go v0.32.3
	k8s.io/cri-api v0.32.3
	k8s.io/kubectl v0.29.3
	sigs.k8s.io/yaml v1.4.0
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/cenkalti/hub v1.0.2 // indirect
	github.com/codegangsta/inject v0.0.0-20150114235600-33e0aa1cb7c0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/opencontainers/selinux v1.12.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/trace v1.35.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/sync v0.16.0
	golang.org/x/text v0.27.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250324211829-b45e905df463 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/utils v0.0.0-20241210054802-24370beab758
	sigs.k8s.io/json v0.0.0-20241010143419-9aa6b5e7a4b3 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.2 // indirect
)

require (
	github.com/alitto/pond v1.9.2
	github.com/dmachard/go-clientsyslog v1.0.1
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/go-ldap/ldap/v3 v3.4.11
	github.com/mitchellh/pointerstructure v1.2.1
	github.com/neuvector/go-rpmdb v0.0.0-20240605184921-0db4de14c27a
	github.com/quay/clair/v2 v2.1.8
	github.com/s3rj1k/go-fanotify/fanotify v0.0.0-20240229202106-bca3154da60a
)

require (
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/MakeNowJust/heredoc v1.0.0 // indirect
	github.com/chai2010/gettext-go v1.0.2 // indirect
	github.com/containerd/cgroups/v3 v3.0.5 // indirect
	github.com/containerd/continuity v0.4.5 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.1 // indirect
	github.com/containerd/plugin v1.0.0 // indirect
	github.com/containerd/ttrpc v1.2.7 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/exponent-io/jsonpath v0.0.0-20151013193312-d6023ce2651d // indirect
	github.com/fatih/camelcase v1.0.0 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/glebarez/go-sqlite v1.20.3 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/go-errors/errors v1.4.2 // indirect
	github.com/go-jose/go-jose/v4 v4.0.5 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/spdystream v0.5.0 // indirect
	github.com/moby/sys/atomicwriter v0.1.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230126093431-47fa9a501578 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/cobra v1.8.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spiffe/go-spiffe/v2 v2.5.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xlab/treeprint v1.2.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	github.com/zeebo/errs v1.4.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.starlark.net v0.0.0-20230525235612-a134d8f9ddca // indirect
	golang.org/x/term v0.33.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gotest.tools/v3 v3.5.1 // indirect
	k8s.io/cli-runtime v0.29.3 // indirect
	k8s.io/component-base v0.31.2 // indirect
	k8s.io/kube-openapi v0.0.0-20241105132330-32ad38e42d3f // indirect
	modernc.org/libc v1.22.2 // indirect
	modernc.org/mathutil v1.5.0 // indirect
	modernc.org/memory v1.5.0 // indirect
	modernc.org/sqlite v1.20.3 // indirect
	sigs.k8s.io/kustomize/api v0.13.5-0.20230601165947-6ce0bf390ce3 // indirect
	sigs.k8s.io/kustomize/kyaml v0.14.3-0.20230601165947-6ce0bf390ce3 // indirect
)

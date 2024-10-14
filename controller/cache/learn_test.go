package cache

import (
	"net"
	"os"
	"syscall"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/graph"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

func preTest() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&utils.LogFormatter{Module: "TEST"})
	log.SetLevel(log.FatalLevel)

	access.CompileUriPermitsMapping()

	connLog := log.New()
	connLog.Out = os.Stdout
	connLog.Formatter = &utils.LogFormatter{Module: "TEST"}
	connLog.Level = log.FatalLevel

	mutexLog := log.New()
	mutexLog.Out = os.Stdout
	mutexLog.Formatter = &utils.LogFormatter{Module: "TEST"}
	mutexLog.Level = log.FatalLevel

	localDev = &common.LocalDevice{
		Host:   &share.CLUSHost{ID: "h1"},
		Ctrler: &share.CLUSController{CLUSDevice: share.CLUSDevice{ID: "c1"}, Leader: true},
	}

	cctx = &Context{
		ConnLog:  connLog,
		MutexLog: mutexLog,
		LocalDev: localDev,
	}

	sctx := scan.Context{
		MutexLog: mutexLog,
		ScanLog:  mutexLog,
	}
	scan.InitContext(&sctx, true)
}

/*
type caseParam struct {
	wls    []*share.CLUSWorkload
	wlgs   []string
	rules  []*share.CLUSPolicyRule
	groups []*share.CLUSGroup
}

func newCase(pm *caseParam) {
	var mockCluster kv.MockCluster
	mockCluster.Init(pm.rules, pm.groups)
	clusHelper = &mockCluster

	for i, wl := range pm.wls {
		wlCacheMap[wl.ID] = &workloadCache{workload: wl, learnedGroupName: pm.wlgs[i]}
	}
	for _, g := range pm.groups {
		groupCacheMap[g.Name] = &groupCache{group: g}
	}
}
*/

func postTest() {
	log.SetLevel(log.DebugLevel)
}

func TestPortAppReplace(t *testing.T) {
	preTest()

	wlGraph = graph.NewGraph()

	// First connection: no application
	ca := nodeAttr{workload: true, managed: true, hostID: "host1"}
	sa := nodeAttr{workload: true, managed: true, hostID: "host1"}
	stip := serverTip{wlPort: 80, mappedPort: 8080}
	conn := share.CLUSConnection{
		AgentID: "a1", HostID: "host1", ClientWL: "client", ServerWL: "server",
		IPProto:  syscall.IPPROTO_TCP,
		PolicyId: 0, PolicyAction: DP_POLICY_ACTION_LEARN,
		Application: 0,
		ClientIP:    net.IPv4(172, 17, 0, 2), ServerIP: net.IPv4(172, 17, 0, 3),
	}

	addConnectToGraph(&conn, &ca, &sa, &stip)

	attr := wlGraph.Attr(conn.ClientWL, policyLink, conn.ServerWL)
	if attr == nil {
		t.Errorf("Policy Link not found: %v -> %v\n", conn.ClientWL, conn.ServerWL)
	}

	a := attr.(*polAttr)
	if a.ports.Cardinality() != 1 && a.apps.Cardinality() != 0 &&
		!a.ports.Equal(utils.NewSet("tcp/80")) {
		t.Errorf("Unexpected policy attr: %+v %+v\n", a.ports, a.apps)
	}

	// Second connection: application identified on the same port
	conn.Application = 1001

	addConnectToGraph(&conn, &ca, &sa, &stip)

	attr = wlGraph.Attr(conn.ClientWL, policyLink, conn.ServerWL)
	if attr == nil {
		t.Errorf("Policy Link not found: %v -> %v\n", conn.ClientWL, conn.ServerWL)
	}

	// -- port entry should be removed
	a = attr.(*polAttr)
	if a.ports.Cardinality() != 0 && a.apps.Cardinality() != 1 &&
		!a.apps.Equal(utils.NewSet(conn.Application)) {
		t.Errorf("Unexpected policy attr: %+v %+v\n", a.ports, a.apps)
	}

	postTest()
}

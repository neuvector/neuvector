package cache

import (
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/graph"
	"github.com/neuvector/neuvector/share"
)

func TestGetAllEndpoints(t *testing.T) {
	preTest()

	accReadAll := access.NewReaderAccessControl()

	wlGraph = graph.NewGraph()

	wlGraph.AddLink("c1", attrLink, dummyEP, &nodeAttr{workload: true, managed: true, hostID: "host1"})
	wlGraph.AddLink("host:h1", attrLink, dummyEP, &nodeAttr{host: true})
	wlGraph.AddLink("workload:w1", attrLink, dummyEP, &nodeAttr{workload: true})
	wlGraph.AddLink("sg1", attrLink, dummyEP, &nodeAttr{ipsvcgrp: true})
	wlGraph.AddLink("nv.sg1", attrLink, dummyEP, &nodeAttr{ipsvcgrp: true})
	wlGraph.AddLink("ag1", attrLink, dummyEP, &nodeAttr{addrgrp: true})
	wlGraph.AddLink("nv.ip.ag1", attrLink, dummyEP, &nodeAttr{addrgrp: true})
	wlGraph.AddLink("ex1", attrLink, dummyEP, &nodeAttr{external: true})

	eps := cacher.GetAllConverEndpoints("", accReadAll)
	if len(eps) != wlGraph.All().Cardinality()-1 {
		t.Errorf("Unexpected endpoint count: %+v %+v\n", wlGraph.All().Cardinality()-1, len(eps))
	}

	postTest()
}

func TestAliasEndpoint(t *testing.T) {
	preTest()

	accReadAll := access.NewReaderAccessControl()

	wl := share.CLUSWorkload{ID: "1", Name: "c1"}
	wlCacheMap[wl.ID] = &workloadCache{workload: &wl, displayName: "container1"}

	wlGraph = graph.NewGraph()

	wlGraph.AddLink("1", attrLink, dummyEP, &nodeAttr{workload: true, managed: true, hostID: "host1"})
	wlGraph.AddLink("host:h1", attrLink, dummyEP, &nodeAttr{host: true})
	wlGraph.AddLink("nv.sg1", attrLink, dummyEP, &nodeAttr{ipsvcgrp: true})
	wlGraph.AddLink("ag1", attrLink, dummyEP, &nodeAttr{addrgrp: true})
	wlGraph.AddLink("ex1", attrLink, dummyEP, &nodeAttr{external: true})

	ConfigEndpoint("1", "c1-x")
	ConfigEndpoint("host:h1", "host:h1-x")
	ConfigEndpoint("nv.sg1", "nv.sg1-x")
	ConfigEndpoint("ag1", "ag1-x")
	ConfigEndpoint("ex1", "ex1-x")

	eps := cacher.GetAllConverEndpoints("", accReadAll)
	for _, ep := range eps {
		if ep.ID == "1" {
			if ep.DisplayName != "c1-x" {
				t.Errorf("Unexpected endpoint display name: %+v\n", ep)
			}
		} else if ep.ID == "host:h1" {
			if ep.DisplayName != "host:h1-x" {
				t.Errorf("Unexpected endpoint display name: %+v\n", ep)
			}
		} else if ep.ID == "nv.sg1" {
			if ep.DisplayName != "nv.sg1-x" {
				t.Errorf("Unexpected endpoint display name: %+v\n", ep)
			}
		} else if ep.ID == "ag1" {
			if ep.DisplayName != "ag1-x" {
				t.Errorf("Unexpected endpoint display name: %+v\n", ep)
			}
		} else if ep.ID == "ex1" {
			if ep.DisplayName != "ex1-x" {
				t.Errorf("Unexpected endpoint display name: %+v\n", ep)
			}
		} else {
			t.Errorf("Unexpected endpoint: %+v\n", ep.ID)
		}
	}

	ConfigEndpoint("1", "")
	ConfigEndpoint("host:h1", "")

	ep, _ := cacher.GetConverEndpoint("1", accReadAll)
	if ep.DisplayName != "container1" {
		t.Errorf("Unexpected endpoint display name after reset: %+v\n", ep)
	}
	ep, _ = cacher.GetConverEndpoint("host:h1", accReadAll)
	if ep.DisplayName != "h1" {
		t.Errorf("Unexpected endpoint display name: %+v\n", ep)
	}

	postTest()
}

package ruleid

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/share"
)

// UUID Version 4 (random)
// A version 4 UUID is randomly generated.
// Thus, for variant 1 (that is, most UUIDs) a random version-4 UUID will have 6 predetermined variant and version bits,
// leaving 122 bits for the randomly generated part, for a total of 2122, or 5.3×1036 (5.3 undecillion) possible version-4 variant-1 UUIDs.
// There are half as many possible version-4 variant-2 UUIDs (legacy GUIDs)
// because there is one less random bit available, 3 bits being consumed for the variant.

// ///// utility
func testSetup(entryCnt int) (*uuidPRuleCache, *share.CLUSProcessProfile) {
	pworker := Init()
	pp := &share.CLUSProcessProfile{
		Group:        "testGrp",
		AlertDisable: false,
		HashEnable:   false,
		Mode:         share.PolicyActionLearn,
		Process:      make([]*share.CLUSProcessProfileEntry, 0),
		CfgType:      share.Learned,
	}

	for i := 0; i < entryCnt; i++ {
		name := fmt.Sprintf("name%d", i)
		path := fmt.Sprintf("/bin/%d", i)
		ppe := &share.CLUSProcessProfileEntry{ // rule
			Name: name, Path: path, Action: share.PolicyActionAllow, UpdatedAt: time.Now().UTC(), CreatedAt: time.Now().UTC(), Uuid: NewUuid(),
		}
		pp.Process = append(pp.Process, ppe)
	}

	return pworker, pp
}

// ///// utility
func removeNilPpe(processes []*share.CLUSProcessProfileEntry) []*share.CLUSProcessProfileEntry {
	list := make([]*share.CLUSProcessProfileEntry, 0)
	for i := range processes {
		if processes[i] == nil {
			continue
		}
		list = append(list, processes[i])
	}
	return list
}

func TestUuidGeneration(t *testing.T) {
	for i := 0; i < 10; i++ {
		uuid_str := NewUuid()
		if len(uuid_str) != 36 {
			t.Errorf("bad uuid: %v\n", uuid_str)
		} else {
			// t.Logf("uuid[%d]: %v", i, uuid_str)
			uu, err := uuid.Parse(uuid_str)
			if err != nil {
				t.Errorf("uuid: failed to parse: %v", uuid_str)
			}

			ver := uu.Version().String()
			if ver != "VERSION_4" {
				// UUID v4 may be used as keys to maps or compared directly.
				t.Errorf("bad uuid version: %v\n", ver)
			}
		}
	}
}

func TestAddProcRules(t *testing.T) {
	pworker, pp := testSetup(10)

	accAdmin := access.NewAdminAccessControl()
	pworker.handleProcessProfile(pp, false, accAdmin)

	// verify by lookup uuid
	for i, ppe := range pp.Process {
		if pRule, ok := pworker.findProcessRule(ppe.Uuid, accAdmin); ok {
			// t.Logf("ppe[%d]: %v, %v, %v", i, ppe.Uuid, pRule.rule.Name, pRule.rule.Path)
			if pRule.Rule.Name != ppe.Name || pRule.Rule.Path != ppe.Path {
				t.Errorf("Mismatched[%d]: %v[%v], %v[%v]\n", i, pRule.Rule.Name, ppe.Name, pRule.Rule.Path, ppe.Path)
			}
		} else {
			t.Errorf("Not found[%d]: %v\n", i, ppe.Uuid)
		}
	}
}

func TestDeleteProcRules(t *testing.T) {

	accAdmin := access.NewAdminAccessControl()

	// Test #1 : remove odd entries
	// t.Logf("Test#1 : remove odd entries")
	pworker, pp := testSetup(10)
	pworker.handleProcessProfile(pp, false, accAdmin)

	//
	list := make([]*share.CLUSProcessProfileEntry, 0)
	for i := range pp.Process {
		if 0 == (i % 2) {
			continue
		}
		list = append(list, pp.Process[i])
		pp.Process[i] = nil
	}

	pp.Process = removeNilPpe(pp.Process)
	pworker.handleProcessProfile(pp, false, accAdmin)

	// verify by lookup uuid: alive
	for _, ppe := range pp.Process {
		if pRule, ok := pworker.findProcessRule(ppe.Uuid, accAdmin); ok {
			// t.Logf("ppe: %v, %v, %v, %v", pRule.bActive, ppe.Uuid, pRule.rule.Name, pRule.rule.Path)
			if pRule.Rule.Name != ppe.Name || pRule.Rule.Path != ppe.Path {
				t.Errorf("Mismatched: %v, %v[%v], %v[%v]\n", pRule.Active, pRule.Rule.Name, ppe.Name, pRule.Rule.Path, ppe.Path)
			}

			if pRule.Active == 0 {
				t.Errorf("Not alive[%s]: even\n", pRule.Rule.Name)
			}
		} else {
			t.Errorf("Not found[%s]: even: %v\n", ppe.Name, ppe.Uuid)
		}
	}

	// verify by lookup uuid: not alive
	for _, ppe := range list {
		// t.Logf("ppe: %v", ppe.Name)
		if pRule, ok := pworker.findProcessRule(ppe.Uuid, accAdmin); ok {
			// t.Logf("ppe: %v, %v, %v, %v", pRule.bActive, ppe.Uuid, pRule.rule.Name, pRule.rule.Path)
			if pRule.Rule.Name != ppe.Name || pRule.Rule.Path != ppe.Path {
				t.Errorf("Mismatched: %v, %v[%v], %v[%v]\n", pRule.Active, pRule.Rule.Name, ppe.Name, pRule.Rule.Path, ppe.Path)
			}

			if pRule.Active == 1 {
				t.Errorf("alive[%s]: even\n", pRule.Rule.Name)
			}
		} else {
			t.Errorf("Not found[%s]: even, %v\n", ppe.Name, ppe.Uuid)
		}
	}

	// Test #2: remove even entries
	// t.Logf("Test#2 : remove even entries")
	pworker, pp = testSetup(10)
	pworker.handleProcessProfile(pp, false, accAdmin)

	list = make([]*share.CLUSProcessProfileEntry, 0)
	for i := range pp.Process {
		if 1 == (i % 2) {
			continue
		}
		list = append(list, pp.Process[i])
		pp.Process[i] = nil
	}

	pp.Process = removeNilPpe(pp.Process)
	pworker.handleProcessProfile(pp, false, accAdmin)

	// verify by lookup uuid
	for _, ppe := range pp.Process {
		if pRule, ok := pworker.findProcessRule(ppe.Uuid, accAdmin); ok {
			// t.Logf("ppe: %v, %v, %v, %v", pRule.bActive, ppe.Uuid, pRule.rule.Name, pRule.rule.Path)
			if pRule.Rule.Name != ppe.Name || pRule.Rule.Path != ppe.Path {
				t.Errorf("Mismatched: odd, %v, %v[%v], %v[%v]\n", pRule.Active, pRule.Rule.Name, ppe.Name, pRule.Rule.Path, ppe.Path)
			}

			// inactive
			if pRule.Active == 0 {
				t.Errorf("Alive[%s]: odd\n", pRule.Rule.Name)
			}
		} else {
			t.Errorf("Not found[%s]: odd %v\n", ppe.Name, ppe.Uuid)
		}
	}

	// verify by lookup uuid: not alive
	for _, ppe := range list {
		if pRule, ok := pworker.findProcessRule(ppe.Uuid, accAdmin); ok {
			// t.Logf("ppe: %v, %v, %v, %v", pRule.bActive, ppe.Uuid, pRule.rule.Name, pRule.rule.Path)
			if pRule.Rule.Name != ppe.Name || pRule.Rule.Path != ppe.Path {
				t.Errorf("Mismatched: %v, %v[%v], %v[%v]\n", pRule.Active, pRule.Rule.Name, ppe.Name, pRule.Rule.Path, ppe.Path)
			}
			if pRule.Active == 1 {
				t.Errorf("alive[%s]: even\n", pRule.Rule.Name)
			}
		} else {
			t.Errorf("Not found[%s]: even, %v\n", ppe.Name, ppe.Uuid)
		}
	}
}

func TestDeleteProcGroup(t *testing.T) {
	pworker, pp := testSetup(10)

	accAdmin := access.NewAdminAccessControl()
	pworker.handleProcessProfile(pp, false, accAdmin)

	// normal operation: wait for a calculation cycle (10 sec)
	// pworker.DeleteProcesProfile(pp)
	// time.Sleep(time.Second * 15)

	// a shortcut: avoid timer
	pworker.handleProcessProfile(pp, true, accAdmin)

	// verify by lookup uuid: alive
	for _, ppe := range pp.Process {
		if pRule, ok := pworker.findProcessRule(ppe.Uuid, accAdmin); ok {
			// t.Logf("ppe: %v, %v, %v, %v", pRule.bActive, ppe.Uuid, pRule.rule.Name, pRule.rule.Path)
			if pRule.Rule.Name != ppe.Name || pRule.Rule.Path != ppe.Path {
				t.Errorf("Mismatched: %v, %v[%v], %v[%v]\n", pRule.Active, pRule.Rule.Name, ppe.Name, pRule.Rule.Path, ppe.Path)
			}

			if pRule.Active == 1 {
				t.Errorf("alive[%s]\n", pRule.Rule.Name)
			}
		} else {
			t.Errorf("Not found[%s]: %v\n", ppe.Name, ppe.Uuid)
		}
	}
}

// Temporarily commented out since this test function is not currently in use.
// func testAddProcRulesMemoryLoop(t *testing.T) {
// 	pworker, pp := testSetup(100000)

// 	accAdmin := access.NewAdminAccessControl()

// 	for {
// 		pworker.handleProcessProfile(pp, false, accAdmin)
// 		time.Sleep(time.Millisecond * 10)
// 	}

// 	// verify by lookup uuid
// 	for i, ppe := range pp.Process {
// 		if pRule, ok := pworker.findProcessRule(ppe.Uuid, accAdmin); ok {
// 			// t.Logf("ppe[%d]: %v, %v, %v", i, ppe.Uuid, pRule.rule.Name, pRule.rule.Path)
// 			if pRule.Rule.Name != ppe.Name || pRule.Rule.Path != ppe.Path {
// 				t.Errorf("Mismatched[%d]: %v[%v], %v[%v]\n", i, pRule.Rule.Name, ppe.Name, pRule.Rule.Path, ppe.Path)
// 			}
// 		} else {
// 			t.Errorf("Not found[%d]: %v\n", i, ppe.Uuid)
// 		}
// 	}
// }

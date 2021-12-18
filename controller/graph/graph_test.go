package graph

import (
	"testing"

	"github.com/neuvector/neuvector/share/utils"
)

// This is a simple test graph.
//
//    +---+                        +---+
//    | A |-------               ->| F |<--
//    +---+       \------>+---+-/  +---+   \--+---+
//                 ------>|#B#|      |        | E |
//    +---+-------/      >+---+      |        +---+
//    | C |             /            v
//    +---+           -/           +---+
//      ----    +---+/             |#G#|
//          \-->|#D#|------------->+---+
//              +---+
//

func makeTestGraph() *Graph {
	g := NewGraph()

	g.AddLink("A", "follows", "B", 0)
	g.AddLink("C", "follows", "B", 0)
	g.AddLink("C", "follows", "D", 0)
	g.AddLink("D", "follows", "B", 0)
	g.AddLink("B", "follows", "F", 0)
	g.AddLink("F", "follows", "G", 0)
	g.AddLink("D", "follows", "G", 0)
	g.AddLink("E", "follows", "F", 0)
	g.AddLink("B", "status", "cool", 0)
	g.AddLink("D", "status", "cool", 0)
	g.AddLink("G", "status", "cool", 0)

	return g
}

func TestOuts(t *testing.T) {
	g := makeTestGraph()

	out := g.Outs("D")

	if out == nil {
		t.Fatalf("Output: %v", out)
	}

	a := utils.NewSet()
	a.Add("cool")
	a.Add("B")
	a.Add("G")

	if !a.Equal(out) {
		t.Errorf("Output: %v", out)
	}
}

func TestOutsLink(t *testing.T) {
	g := makeTestGraph()

	out := g.OutsByLink("B", "follows")
	if out == nil {
		t.Fatalf("Output: %v", out)
	}

	a := utils.NewSet()
	a.Add("F")

	if !a.Equal(out) {
		t.Errorf("Output: %v", out)
	}
}

func TestNoIn(t *testing.T) {
	g := makeTestGraph()

	out := g.NoIn()
	if out == nil {
		t.Fatalf("Output: %v", out)
	}

	a := utils.NewSet()
	a.Add("A")
	a.Add("C")
	a.Add("E")

	if !a.Equal(out) {
		t.Errorf("Output: %v", out)
	}
}

func nodeCallbackTrue(node string) bool {
	return true
}

func nodeCallbackAB(node string) bool {
	if node == "A" || node == "B" {
		return true
	} else {
		return false
	}
}

func TestConn(t *testing.T) {
	g := makeTestGraph()

	out := g.Connected("A", nodeCallbackTrue)
	if out == nil {
		t.Fatalf("Output: %v", out)
	}

	a := utils.NewSet()
	a.Add("A")
	a.Add("B")
	a.Add("C")
	a.Add("D")
	a.Add("E")
	a.Add("F")
	a.Add("G")
	a.Add("cool")

	if !a.Equal(out) {
		t.Errorf("Output: %v", out)
	}
}

func TestConnNonNode(t *testing.T) {
	g := makeTestGraph()

	out := g.Connected("A", nil)
	if out == nil {
		t.Fatalf("Output: %v", out)
	}

	a := utils.NewSet()
	a.Add("A")

	if !a.Equal(out) {
		t.Errorf("Output: %v", out)
	}
}

func TestConnPartial(t *testing.T) {
	g := makeTestGraph()

	out := g.Connected("A", nodeCallbackAB)
	if out == nil {
		t.Fatalf("Output: %v", out)
	}

	a := utils.NewSet()
	a.Add("A")
	a.Add("B")

	if !a.Equal(out) {
		t.Errorf("Output: %v", out)
	}
}

func TestConnLink(t *testing.T) {
	g := makeTestGraph()

	out := g.ConnectedByLink("A", "follows", nodeCallbackTrue)
	if out == nil {
		t.Fatalf("Output: %v", out)
	}

	a := utils.NewSet()
	a.Add("A")
	a.Add("B")
	a.Add("C")
	a.Add("D")
	a.Add("E")
	a.Add("F")
	a.Add("G")

	if !a.Equal(out) {
		t.Errorf("Output: %v", out)
	}
}

func TestDeleteLink(t *testing.T) {
	g := makeTestGraph()

	g.DeleteLink("A", "follows", "B")
	in := g.Ins("B")

	i := utils.NewSet()
	i.Add("C")
	i.Add("D")

	if !i.Equal(in) {
		t.Errorf("Output: %v", in)
	}

	g.DeleteLink("D", "follows", "G")
	g.DeleteLink("D", "status", "cool")
	out := g.Outs("D")

	o := utils.NewSet()
	o.Add("B")

	if !o.Equal(out) {
		t.Errorf("Output: %v", out)
	}

	g.DeleteLink("D", "follows", "B")
	out = g.Outs("D")

	if out.Cardinality() != 0 {
		t.Errorf("Output: %v", out)
	}
}

func TestDeleteNode(t *testing.T) {
	g := makeTestGraph()

	count := g.All().Cardinality()

	g.DeleteNode("B")

	if count-1 != g.All().Cardinality() {
		t.Errorf("Output: %v", g.All())
	}

	if g.Outs("D").Cardinality() != 2 {
		t.Errorf("Output: %v", g.Outs("D"))
	}

	if g.Ins("F").Cardinality() != 1 {
		t.Errorf("Output: %v", g.Ins("F"))
	}
}

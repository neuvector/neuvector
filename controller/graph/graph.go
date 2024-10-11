package graph

import (
	"reflect"

	"github.com/neuvector/neuvector/share/utils"
)

type NewLinkCallback func(src, link, dst string)
type DelNodeCallback func(node string)
type DelLinkCallback func(src, link, dst string)
type UpdateLinkAttrCallback func(src, link, dst string)

type ConnectedNodeCallback func(node string) bool
type PurgeOutLinkCallback func(src, link, dst string, attr interface{}, param interface{}) bool

// Links leads to the other end's nodes, indexed by node name
type graphLink struct {
	ends map[string]interface{} // node end name
}

// Every node has incoming and outgoing links indexed by link name
type graphNode struct {
	ins  map[string]*graphLink // link name
	outs map[string]*graphLink
}

type Graph struct {
	nodes            map[string]*graphNode // node name
	cbNewLink        NewLinkCallback
	cbDelNode        DelNodeCallback
	cbDelLink        DelLinkCallback
	cbUpdateLinkAttr UpdateLinkAttrCallback
}

func NewGraph() *Graph {
	return &Graph{
		nodes: make(map[string]*graphNode),
	}
}

func (g *Graph) RegisterNewLinkHook(cb NewLinkCallback) {
	g.cbNewLink = cb
}

func (g *Graph) RegisterDelNodeHook(cb DelNodeCallback) {
	g.cbDelNode = cb
}

func (g *Graph) RegisterDelLinkHook(cb DelLinkCallback) {
	g.cbDelLink = cb
}

func (g *Graph) RegisterUpdateLinkAttrHook(cb UpdateLinkAttrCallback) {
	g.cbUpdateLinkAttr = cb
}

func (g *Graph) Reset() {
	g.nodes = make(map[string]*graphNode)
}

func (g *Graph) AddLink(src, link, dst string, attr interface{}) {
	var gn *graphNode
	var gl *graphLink
	var ok, newlink, updattr bool

	if gn, ok = g.nodes[src]; !ok {
		gl = &graphLink{ends: make(map[string]interface{})}
		gl.ends[dst] = attr

		gn = &graphNode{
			ins:  make(map[string]*graphLink),
			outs: make(map[string]*graphLink),
		}
		gn.outs[link] = gl

		g.nodes[src] = gn

		newlink = true
	} else if gl, ok = gn.outs[link]; !ok {
		gl = &graphLink{ends: make(map[string]interface{})}
		gl.ends[dst] = attr

		gn.outs[link] = gl

		newlink = true
	} else if _, ok = gl.ends[dst]; !ok {
		gl.ends[dst] = attr

		newlink = true
	} else {
		if !reflect.DeepEqual(gl.ends[dst], attr) {
			gl.ends[dst] = attr
			updattr = true
		}
	}

	if gn, ok = g.nodes[dst]; !ok {
		gl = &graphLink{ends: make(map[string]interface{})}
		gl.ends[src] = attr

		gn = &graphNode{
			ins:  make(map[string]*graphLink),
			outs: make(map[string]*graphLink),
		}
		gn.ins[link] = gl

		g.nodes[dst] = gn

		newlink = true
	} else if gl, ok = gn.ins[link]; !ok {
		gl = &graphLink{ends: make(map[string]interface{})}
		gl.ends[src] = attr

		gn.ins[link] = gl

		newlink = true
	} else if _, ok = gl.ends[src]; !ok {
		gl.ends[src] = attr

		newlink = true
	} else {
		if !reflect.DeepEqual(gl.ends[src], attr) {
			gl.ends[src] = attr
			updattr = true
		}
	}

	if newlink && g.cbNewLink != nil {
		g.cbNewLink(src, link, dst)
	}
	if updattr && g.cbUpdateLinkAttr != nil {
		g.cbUpdateLinkAttr(src, link, dst)
	}
}

func (g *Graph) Attr(src, link, dst string) interface{} {
	if s, ok := g.nodes[src]; ok {
		if gl, ok := s.outs[link]; ok {
			if attr, ok := gl.ends[dst]; ok {
				return attr
			}
		}
	}

	return nil
}

func (g *Graph) DeleteLink(src, link, dst string) {
	var s, d *graphNode
	var ok bool

	if s, ok = g.nodes[src]; !ok {
		return
	}
	if d, ok = g.nodes[dst]; !ok {
		return
	}

	if gl, ok := s.outs[link]; ok {
		if _, ok = gl.ends[dst]; ok {
			delete(gl.ends, dst)
			if len(gl.ends) == 0 {
				delete(s.outs, link)

				if g.cbDelLink != nil {
					g.cbDelLink(src, link, dst)
				}
			}
		}
	}

	if gl, ok := d.ins[link]; ok {
		if _, ok = gl.ends[src]; ok {
			delete(gl.ends, src)
			if len(gl.ends) == 0 {
				delete(d.ins, link)

				if g.cbDelLink != nil {
					g.cbDelLink(src, link, dst)
				}
			}
		}
	}
}

func (g *Graph) DeleteNode(node string) string {
	var gn *graphNode
	var ok bool

	if gn, ok = g.nodes[node]; !ok {
		return ""
	}

	for link, gl := range gn.ins {
		for n := range gl.ends {
			g.DeleteLink(n, link, node)
		}
	}

	for link, gl := range gn.outs {
		for n := range gl.ends {
			g.DeleteLink(node, link, n)
		}
	}

	delete(g.nodes, node)

	if g.cbDelNode != nil {
		g.cbDelNode(node)
	}

	return node
}

func (g *Graph) Node(v string) string {
	if _, ok := g.nodes[v]; ok {
		return v
	} else {
		return ""
	}
}

func (g *Graph) All() utils.Set {
	ret := utils.NewSet()
	for v := range g.nodes {
		ret.Add(v)
	}
	return ret
}

func (g *Graph) NoIn() utils.Set {
	ret := utils.NewSet()
	for v, n := range g.nodes {
		if len(n.ins) == 0 {
			ret.Add(v)
		}
	}

	return ret
}

func (g *Graph) NoInByLink(link string) utils.Set {
	ret := utils.NewSet()
	for v, n := range g.nodes {
		if _, ok := n.ins[link]; !ok {
			ret.Add(v)
		} else if len(n.ins[link].ends) == 0 {
			ret.Add(v)
		}
	}

	return ret
}

func (g *Graph) NoOut() utils.Set {
	ret := utils.NewSet()
	for v, n := range g.nodes {
		if len(n.outs) == 0 {
			ret.Add(v)
		}
	}

	return ret
}

func (g *Graph) NoOutByLink(link string) utils.Set {
	ret := utils.NewSet()
	for v, n := range g.nodes {
		if _, ok := n.outs[link]; !ok {
			ret.Add(v)
		} else if len(n.outs[link].ends) == 0 {
			ret.Add(v)
		}
	}

	return ret
}

func (g *Graph) Ins(node string) utils.Set {
	if _, ok := g.nodes[node]; !ok {
		return nil
	}

	ret := utils.NewSet()
	n := g.nodes[node]
	for _, l := range n.ins {
		for v := range l.ends {
			ret.Add(v)
		}
	}

	return ret
}

func (g *Graph) InsByLink(node string, link string) utils.Set {
	if _, ok := g.nodes[node]; !ok {
		return nil
	}

	ret := utils.NewSet()
	n := g.nodes[node]
	if gl, ok := n.ins[link]; !ok {
		return ret
	} else {
		for v := range gl.ends {
			ret.Add(v)
		}
	}

	return ret
}

func (g *Graph) Outs(node string) utils.Set {
	if _, ok := g.nodes[node]; !ok {
		return nil
	}

	ret := utils.NewSet()
	n := g.nodes[node]
	for _, l := range n.outs {
		for v := range l.ends {
			ret.Add(v)
		}
	}

	return ret
}

func (g *Graph) OutsByLink(node string, link string) utils.Set {
	if _, ok := g.nodes[node]; !ok {
		return nil
	}

	ret := utils.NewSet()
	n := g.nodes[node]
	if gl, ok := n.outs[link]; !ok {
		return ret
	} else {
		for v := range gl.ends {
			ret.Add(v)
		}
	}

	return ret
}

func (g *Graph) Both(node string) utils.Set {
	if _, ok := g.nodes[node]; !ok {
		return nil
	}

	return g.Ins(node).Union(g.Outs(node))
}

func (g *Graph) BothByLink(node string, link string) utils.Set {
	if _, ok := g.nodes[node]; !ok {
		return nil
	}

	return g.InsByLink(node, link).Union(g.OutsByLink(node, link))
}

func (g *Graph) Connected(node string, cb ConnectedNodeCallback) utils.Set {
	if _, ok := g.nodes[node]; !ok {
		return nil
	}

	ret := utils.NewSet()
	ret.Add(node)
	q := []string{node}

	for len(q) > 0 {
		// Remove head
		node, q = q[0], q[1:]

		both := g.Both(node)
		for n := range both.Iter() {
			if cb != nil && cb(n.(string)) {
				if !ret.Contains(n) {
					ret.Add(n)
					q = append(q, n.(string))
				}
			}
		}
	}

	return ret
}

func (g *Graph) ConnectedByLink(node string, link string, cb ConnectedNodeCallback) utils.Set {
	if _, ok := g.nodes[node]; !ok {
		return nil
	}

	ret := utils.NewSet()
	ret.Add(node)
	q := []string{node}

	for len(q) > 0 {
		// Remove head
		node, q = q[0], q[1:]

		both := g.BothByLink(node, link)
		for n := range both.Iter() {
			if cb != nil && cb(n.(string)) {
				if !ret.Contains(n) {
					ret.Add(n)
					q = append(q, n.(string))
				}
			}
		}
	}

	return ret
}

func (g *Graph) BetweenDirLinks(src string, dst string) map[string]interface{} {
	ret := make(map[string]interface{})
	if n, ok := g.nodes[src]; ok {
		for ln, l := range n.outs {
			if attr, ok := l.ends[dst]; ok {
				ret[ln] = attr
			}
		}
	}
	return ret
}

func (g *Graph) PurgeOutLinks(src string, cb PurgeOutLinkCallback, param interface{}) {
	if n, ok := g.nodes[src]; ok {
		for ln, l := range n.outs {
			for dst, attr := range l.ends {
				// Delete map key in range loop is safe
				if cb(src, ln, dst, attr, param) {
					delete(l.ends, dst)
					if len(l.ends) == 0 {
						delete(n.outs, ln)
					}
				}
			}
		}
	}
}

func (g *Graph) GetNodeCount() int {
	return len(g.nodes)
}

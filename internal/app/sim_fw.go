package app

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// simFirewall imitates the DrayOS IP object / IP group / filter rule commands
// used by MAC blocking, for the demo router and the tests.
type simFirewall struct {
	mu    sync.Mutex
	objs  map[int]*simObj
	grps  map[int]*simGrp
	rules map[[2]int]*simRule
	// RejectMAC makes "-a 4 <mac>" silently ignored (firmware without MAC objects).
	RejectMAC bool
	Log       []string
}

type simObj struct{ name, typ, mac string }
type simGrp struct {
	name    string
	members []int
}
type simRule struct {
	enabled              bool
	comment, src, action string
}

func newSimFirewall() *simFirewall {
	return &simFirewall{objs: map[int]*simObj{}, grps: map[int]*simGrp{}, rules: map[[2]int]*simRule{}}
}

var (
	reSimObj  = regexp.MustCompile(`^object ip obj (\d+) (-v|-n (\S+)|-i (\d)|-a 4 (\S+))$`)
	reSimGrp  = regexp.MustCompile(`^object ip grp (\d+) (-v|-n (\S+)|-i (\d)|-a((?: \d+)+))$`)
	reSimRule = regexp.MustCompile(`^ipf rule (\d+) (\d+) (-v|-e ([01]))$`)
)

func (f *simFirewall) obj(i int) *simObj {
	if f.objs[i] == nil {
		f.objs[i] = &simObj{typ: "single", mac: zeroMAC}
	}
	return f.objs[i]
}

func (f *simFirewall) grp(i int) *simGrp {
	if f.grps[i] == nil {
		f.grps[i] = &simGrp{}
	}
	return f.grps[i]
}

func (f *simFirewall) rule(s, r int) *simRule {
	k := [2]int{s, r}
	if f.rules[k] == nil {
		f.rules[k] = &simRule{comment: "<null>", src: "Any", action: "Pass Immediately"}
	}
	return f.rules[k]
}

// handle answers a firewall command; ok=false when it is not one.
func (f *simFirewall) handle(cmd string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := reSimObj.FindStringSubmatch(cmd); m != nil {
		i, _ := strconv.Atoi(m[1])
		o := f.obj(i)
		switch {
		case m[2] == "-v":
			return fmt.Sprintf(" IP Object Profile %d\n Name   :[%s]\n Interface:[Lan]\n Address type:[%s]\n Start ip address:[0.0.0.0]\n End/Mask ip address:[0.0.0.0]\n MAC Address:[%s]\n Invert Selection:[0]", i, o.name, o.typ, strings.ToLower(o.mac)), true
		case m[3] != "":
			o.name = m[3]
		case m[5] != "":
			if !f.RejectMAC {
				o.typ, o.mac = "mac", strings.ToUpper(m[5])
			}
		}
		f.Log = append(f.Log, cmd)
		return "OK.", true
	}
	if m := reSimGrp.FindStringSubmatch(cmd); m != nil {
		i, _ := strconv.Atoi(m[1])
		g := f.grp(i)
		switch {
		case m[2] == "-v":
		case m[3] != "":
			g.name = m[3]
		case m[5] != "":
			g.members = nil
			for _, x := range strings.Fields(m[5]) {
				n, _ := strconv.Atoi(x)
				g.members = append(g.members, n)
			}
		}
		if m[2] != "-v" {
			f.Log = append(f.Log, cmd)
		}
		var b strings.Builder
		fmt.Fprintf(&b, " IP Group Profile %d\n Name   :[%s]\n Interface:[Lan]\n Included ip object index:\n", i, g.name)
		for k := range 12 {
			v := 0
			if k < len(g.members) {
				v = g.members[k]
			}
			fmt.Fprintf(&b, " [%d:][%d]\n", k, v)
		}
		if m[2] != "-v" {
			b.WriteString(" Set ok!")
		}
		return b.String(), true
	}
	if m := reSimRule.FindStringSubmatch(cmd); m != nil {
		s, _ := strconv.Atoi(m[1])
		ri, _ := strconv.Atoi(m[2])
		r := f.rule(s, ri)
		if m[4] != "" {
			r.enabled = m[4] == "1"
			f.Log = append(f.Log, cmd)
			return "Setting saved.", true
		}
		st := map[bool]string{true: "Enable", false: "Disable"}[r.enabled]
		return fmt.Sprintf("Filter Set %d Rule %d:\nStatus : %s\nComments: %s\nDirection    : LAN/DMZ/RT/VPN -> WAN\nSource IP    : %s\nDestination IP: Any\nService Type : Any\nPass or Block           : %s\nBranch to Other Filter Set: None", s, ri, st, r.comment, r.src, r.action), true
	}
	return "", false
}

// prepareDemoRule builds the rule an admin would create in the web UI.
func (f *simFirewall) prepareDemoRule(set, rule int, groupName string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.rule(set, rule)
	r.comment, r.src, r.action = "DrayPulse block", "Group "+groupName, "Block Immediately"
}

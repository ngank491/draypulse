package app

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// simFirewall imitates the DrayOS 4.4 IP objects, IP groups and data filter
// rules for the demo router and the tests. Its "-v" output copies what a
// Vigor2926 plus / Vigor3912S prints.
type simFirewall struct {
	mu        sync.Mutex
	objs      map[int]*simObj
	grps      map[int]*simGrp
	rules     map[[2]int]*simRule
	dfOn      bool
	startSet  int
	Sets      int // filter sets (12 on Vigor2926 plus, 50 on Vigor3912S)
	RulesPer  int // rules per set (7 / 30)
	Log       []string
	IgnoreObj bool // "-a 4 MAC" answers OK but stores nothing
	saved     *simFirewall
}

type simObj struct {
	name, iface, typ, ip, mac string
}

type simGrp struct {
	name, iface string
	members     [12]int
}

type simRule struct {
	on              bool
	comment, src    string
	block           bool
	g1, g2          int
	src1, src2      string
	direction, macb int
}

func newSimFirewall() *simFirewall {
	return &simFirewall{objs: map[int]*simObj{}, grps: map[int]*simGrp{}, rules: map[[2]int]*simRule{}, dfOn: true, startSet: 1, Sets: 12, RulesPer: 7}
}

func (f *simFirewall) obj(i int) *simObj {
	if f.objs[i] == nil {
		f.objs[i] = &simObj{iface: "Any", typ: "mask", ip: "0.0.0.0", mac: "00:00:00:00:00:00"}
	}
	return f.objs[i]
}

func (f *simFirewall) grp(i int) *simGrp {
	if f.grps[i] == nil {
		f.grps[i] = &simGrp{iface: "Any"}
	}
	return f.grps[i]
}

func (f *simFirewall) rule(s, r int) *simRule {
	k := [2]int{s, r}
	if f.rules[k] == nil {
		f.rules[k] = &simRule{}
	}
	return f.rules[k]
}

// SetRule puts an admin rule in place (tests).
func (f *simFirewall) SetRule(s, r int, on bool, comment string, block bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	x := f.rule(s, r)
	x.on, x.comment, x.block = on, comment, block
}

// Saved is the configuration in flash; Reboot goes back to it (DrayPulse
// never commits, so a reboot loses its changes).
func (f *simFirewall) Save() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saved = f.clone()
}

func (f *simFirewall) Reboot() {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.saved
	if s == nil {
		s = newSimFirewall()
		s.dfOn, s.startSet = f.dfOn, f.startSet
	}
	c := s.clone()
	f.objs, f.grps, f.rules, f.dfOn, f.startSet = c.objs, c.grps, c.rules, c.dfOn, c.startSet
}

func (f *simFirewall) clone() *simFirewall {
	c := &simFirewall{objs: map[int]*simObj{}, grps: map[int]*simGrp{}, rules: map[[2]int]*simRule{}, dfOn: f.dfOn, startSet: f.startSet}
	for k, v := range f.objs {
		x := *v
		c.objs[k] = &x
	}
	for k, v := range f.grps {
		x := *v
		c.grps[k] = &x
	}
	for k, v := range f.rules {
		x := *v
		c.rules[k] = &x
	}
	return c
}

// Obj and Grp read the state (tests).
func (f *simFirewall) Obj(i int) simObj {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o := f.objs[i]; o != nil {
		return *o
	}
	return simObj{}
}

func (f *simFirewall) Grp(i int) [12]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if g := f.grps[i]; g != nil {
		return g.members
	}
	return [12]int{}
}

func (f *simFirewall) Rule(s, r int) simRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	if x := f.rules[[2]int{s, r}]; x != nil {
		return *x
	}
	return simRule{}
}

func (f *simFirewall) DF() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dfOn
}

func (f *simFirewall) Writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Log...)
}

var (
	reSimObj  = regexp.MustCompile(`^object ip obj (\d+) (.+)$`)
	reSimGrp  = regexp.MustCompile(`^object ip grp (\d+) (.+)$`)
	reSimRule = regexp.MustCompile(`^ipf rule (\d+) (\d+) (.+)$`)
	reSimOpt  = regexp.MustCompile(`-([A-Za-z]) ("[^"]*"|\S+)`)
)

func (f *simFirewall) handle(cmd string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case cmd == "ipf set -v":
		if !f.dfOn {
			return "\nData Filter: Disable\nLog Flag   : Disable\n\nActions for packet not matching any rule:\n  Pass or Block     : Pass\n", true
		}
		return fmt.Sprintf("\nData Filter: Enable (Start Filter Set = %d)\n  Pass or Block     : Pass\n", f.startSet), true
	case strings.HasPrefix(cmd, "ipf set -d "):
		f.Log = append(f.Log, cmd)
		n, _ := strconv.Atoi(strings.TrimPrefix(cmd, "ipf set -d "))
		f.dfOn = n > 0
		if n > 0 {
			f.startSet = n
		}
		return "", true
	case cmd == "ipf rule ?":
		return fmt.Sprintf("\nUsage:\n\nipf rule s r [-<command> <parameter> | ...\n\ns: set, range 1-%d.\nr: rule, range 1-%d.\n", f.Sets, f.RulesPer), true
	}
	if m := reSimObj.FindStringSubmatch(cmd); m != nil {
		i, _ := strconv.Atoi(m[1])
		o := f.obj(i)
		if m[2] == "-v" {
			typ := o.typ
			return fmt.Sprintf(" IP Object Profile %d\n Name   :[%s]\n Interface:[%s]\n Address type:[%s]\n Start ip address:[%s]\n End/Mask ip address:[0.0.0.0]\n MAC Address:[%s]\n Invert Selection:[0]\n",
				i, o.name, o.iface, typ, o.ip, strings.ToUpper(o.mac)), true
		}
		f.Log = append(f.Log, cmd)
		a := strings.Fields(m[2])
		switch a[0] {
		case "-n":
			o.name = strings.Trim(strings.Join(a[1:], " "), `"`)
		case "-i":
			o.iface = map[string]string{"0": "Any", "1": "Lan", "3": "Wan"}[a[1]]
		case "-a":
			switch a[1] {
			case "4":
				if !f.IgnoreObj || a[2] == "00:00:00:00:00:00" {
					o.mac = a[2]
					if a[2] != "00:00:00:00:00:00" {
						o.typ = "mac"
					}
				}
			case "1":
				o.typ, o.ip = "single", a[2]
			case "0":
				o.typ, o.ip = "mask", a[2]
			}
		}
		return "OK.", true
	}
	if m := reSimGrp.FindStringSubmatch(cmd); m != nil {
		i, _ := strconv.Atoi(m[1])
		g := f.grp(i)
		if m[2] != "-v" {
			f.Log = append(f.Log, cmd)
			a := strings.Fields(m[2])
			switch a[0] {
			case "-n":
				if len(a) < 2 || a[1] == `""` {
					return "ip grp Usage:\n...\nPlease input the name(Max. length is 15)", true
				}
				g.name = a[1]
			case "-i":
				g.iface = map[string]string{"0": "Any", "1": "Lan", "3": "Wan"}[a[1]]
			case "-a":
				var mem [12]int
				for k, x := range strings.Fields(strings.Trim(strings.Join(a[1:], " "), `"`)) {
					if k < 12 {
						mem[k], _ = strconv.Atoi(x)
					}
				}
				g.members = mem
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, " IP Group Profile %d\n Name   :[%s]\n Interface:[%s]\n Included ip object index:\n", i, g.name, g.iface)
		for k, x := range g.members {
			fmt.Fprintf(&b, " [%d:][%d]\n", k, x)
		}
		if m[2] != "-v" {
			b.WriteString("\nSet ok!\n")
		}
		return b.String(), true
	}
	if m := reSimRule.FindStringSubmatch(cmd); m != nil {
		s, _ := strconv.Atoi(m[1])
		r, _ := strconv.Atoi(m[2])
		if s < 1 || s > f.Sets || r < 1 || r > f.RulesPer {
			return "% invalid set/rule", true
		}
		x := f.rule(s, r)
		if m[3] == "-v" {
			src := "Any"
			var parts []string
			if x.g1 > 0 {
				parts = append(parts, fmt.Sprintf("(g1)IP Group%d", x.g1))
			}
			if x.g2 > 0 {
				parts = append(parts, fmt.Sprintf("(g2)IP Group%d", x.g2))
			}
			if len(parts) > 0 {
				src = strings.Join(parts, ", ") + ", "
			}
			comment := x.comment
			if comment == "" {
				comment = "<null>"
			}
			act := "Pass Immediately"
			if x.block {
				act = "Block Immediately"
			}
			return fmt.Sprintf("\nFilter Set %d Rule %d:\n\nStatus  : %s\nComments: %s\n\nDirection     : LAN/DMZ/RT/VPN -> WAN\nSource IP     : %s\nDestination IP: Any\nService Type  : Any\n\nPass or Block             : %s\nMac Bind IP               : Non-Strict\n",
				s, r, map[bool]string{true: "Enable", false: "Disable"}[x.on], comment, src, act), true
		}
		f.Log = append(f.Log, cmd)
		for _, o := range reSimOpt.FindAllStringSubmatch(m[3], -1) {
			v := strings.Trim(o[2], `"`)
			switch o[1] {
			case "e":
				x.on = v == "1"
			case "M":
				x.comment = v
			case "F":
				x.block = strings.HasPrefix(v, "1")
			case "s":
				p := strings.Fields(v)
				if len(p) == 3 && p[0] == "g" {
					n, _ := strconv.Atoi(p[2])
					if p[1] == "1" {
						x.g1 = n
					} else {
						x.g2 = n
					}
				}
				if len(p) == 2 && p[0] == "u" { // any
					x.g1, x.g2 = 0, 0
				}
			case "U":
				if v == "0" && r > 1 { // move up: swap with the rule above
					k1, k2 := [2]int{s, r}, [2]int{s, r - 1}
					f.rules[k1], f.rules[k2] = f.rule(s, r-1), x
				}
			}
		}
		return "\nOK", true
	}
	return "", false
}

// blocked reports whether traffic from mac would hit a DrayPulse block rule
// that the data filter applies (tests).
func (f *simFirewall) blocked(mac string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.dfOn {
		return false
	}
	for r := 1; r <= f.RulesPer; r++ {
		x := f.rules[[2]int{f.startSet, r}]
		if x == nil || !x.on {
			continue
		}
		hit := x.g1 == 0 && x.g2 == 0 // Any
		for _, g := range []int{x.g1, x.g2} {
			if g == 0 || f.grps[g] == nil {
				continue
			}
			for _, oi := range f.grps[g].members {
				if o := f.objs[oi]; oi > 0 && o != nil && o.typ == "mac" && strings.EqualFold(o.mac, mac) {
					hit = true
				}
			}
		}
		if hit {
			return x.block
		}
	}
	return false
}

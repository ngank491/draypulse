package app

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ---------- Blocking with a data filter rule and MAC IP objects ----------
//
// DrayTek documents a firewall rule with an IP object of type MAC as the way
// to block one device whatever its IP (Bind IP to MAC is a DHCP reservation:
// a "blocked" device just gets another IP, and the router keeps one entry
// per MAC and LAN). DrayPulse keeps on each router:
//
//   - one IP object per blocked device (type MAC) or IP-only block (type
//     single), named "DP-<MAC>" / "DPI<IP>", taken from index 192 downwards,
//   - IP groups 32, 31, 30, 29 ("DrayPulse1" … "DrayPulse4"), 12 objects each,
//   - rules in the data filter's start set, LAN → WAN, Block Immediately, MAC
//     Bind non-strict: "DrayPulse" with source groups 32 (+31), and from the
//     25th block "DrayPulse2" with groups 30 (+29). DrayOS takes at most two
//     IP groups as a rule's source, hence 24 per rule.
//
// Every change converges the router to the wanted list and is read back. The
// rule is enabled only after its groups hold the objects and disabled before
// they are emptied (an empty group must never be a rule's source). Nothing
// is committed to flash: the comparison every 5 minutes restores what a
// reboot lost.

const (
	fwComment  = "DrayPulse"
	fwObjTop   = 192
	fwObjLow   = 100
	fwPerGroup = 12
)

// fwUnit is one DrayPulse rule and its two source groups.
type fwUnit struct {
	Comment string
	G1, G2  int
}

var fwUnits = []fwUnit{{fwComment, 32, 31}, {fwComment + "2", 30, 29}}

var fwGroups = []int{32, 31, 30, 29}

const fwPerRule = 2 * fwPerGroup

// fwMax is how many devices/IPs DrayPulse can block per router.
var fwMax = fwPerGroup * len(fwGroups)

// fwUnitsFor: how many rules n blocks need.
func fwUnitsFor(n int) int { return (n + fwPerRule - 1) / fwPerRule }

func grpTag(g int) string { return fmt.Sprintf("Group%d", g) }

// fwLayout is where DrayPulse's pieces sit on one router (kv "fw:<id>").
type fwLayout struct {
	Set      int            `json:"set"`      // rule slot
	Rule     int            `json:"rule"`     //
	Rule2    int            `json:"rule2"`    // the second rule (25th block on)
	Objects  map[string]int `json:"objects"`  // key → IP object index
	TurnedOn bool           `json:"turnedOn"` // DrayPulse switched the data filter on
	Sets     int            `json:"sets"`     // limits of this firmware
	Rules    int            `json:"rules"`
}

// fwKey identifies a block: "mac:AA:BB:…" or "ip:192.168.1.5".
func fwKeyMAC(mac string) string { return "mac:" + mac }
func fwKeyIP(ip string) string   { return "ip:" + ip }

func fwObjName(key string) string {
	if mac, ok := strings.CutPrefix(key, "mac:"); ok {
		return "DP-" + strings.ReplaceAll(mac, ":", "")
	}
	ip := strings.TrimPrefix(key, "ip:")
	var b strings.Builder
	b.WriteString("DPI")
	for _, p := range strings.Split(ip, ".") {
		n, _ := strconv.Atoi(p)
		fmt.Fprintf(&b, "%03d", n)
	}
	return b.String()
}

// fwWriteAllowed are the only firewall changes DrayPulse can make. Indices
// and values are constrained; the code also checks each object, group and
// rule is DrayPulse's (by name/comment) before changing it.
var fwWriteAllowed = []*regexp.Regexp{
	regexp.MustCompile(`^ipf set -v$`),
	regexp.MustCompile(`^ipf set -d \d{1,2}$`),
	regexp.MustCompile(`^ipf rule \?$`),
	regexp.MustCompile(`^ipf rule \d{1,2} \d{1,2} -v$`),
	regexp.MustCompile(`^ipf rule \d{1,2} \d{1,2} -e 1 -D 0 -s "g 1 32" -F "1 0" -m "0 0" -M "DrayPulse"$`),
	regexp.MustCompile(`^ipf rule \d{1,2} \d{1,2} -e 1 -D 0 -s "g 1 30" -F "1 0" -m "0 0" -M "DrayPulse2"$`),
	regexp.MustCompile(`^ipf rule \d{1,2} \d{1,2} -s "g 2 (31|29|0)"$`),
	regexp.MustCompile(`^ipf rule \d{1,2} \d{1,2} -e 0$`),
	regexp.MustCompile(`^ipf rule \d{1,2} \d{1,2} -U 0$`),
	regexp.MustCompile(`^object ip obj (1\d\d|\d{1,2}) -v$`),
	regexp.MustCompile(`^object ip obj (1\d\d) -n (DP-[0-9A-F]{12}|DPI\d{12}|"")$`),
	regexp.MustCompile(`^object ip obj (1\d\d) -i [01]$`),
	regexp.MustCompile(`^object ip obj (1\d\d) -a 4 [0-9a-f]{2}(:[0-9a-f]{2}){5}$`),
	regexp.MustCompile(`^object ip obj (1\d\d) -a 1 \d{1,3}(\.\d{1,3}){3}$`),
	regexp.MustCompile(`^object ip obj (1\d\d) -a 0 0\.0\.0\.0 0\.0\.0\.0$`),
	regexp.MustCompile(`^object ip grp (29|30|31|32) -v$`),
	regexp.MustCompile(`^object ip grp (29|30|31|32) -n DrayPulse[1-4]$`),
	regexp.MustCompile(`^object ip grp (29|30|31|32) -i [01]$`),
	regexp.MustCompile(`^object ip grp (29|30|31|32) -a "\d{1,3}( \d{1,3}){11}"$`),
}

func fwCommandAllowed(cmd string) bool {
	for _, re := range fwWriteAllowed {
		if re.MatchString(cmd) {
			if i := objIndex(cmd); i > 0 && strings.Contains(cmd, " -v") == false && (i < fwObjLow || i > fwObjTop) {
				return false
			}
			return true
		}
	}
	return false
}

var reObjIdx = regexp.MustCompile(`^object ip obj (\d+) `)

func objIndex(cmd string) int {
	if m := reObjIdx.FindStringSubmatch(cmd); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// ---------- parsing the "-v" views ----------

var (
	reFwName   = regexp.MustCompile(`(?m)^\s*Name\s*:\[([^\]]*)\]`)
	reFwType   = regexp.MustCompile(`(?m)^\s*Address type:\[([^\]]*)\]`)
	reFwIP     = regexp.MustCompile(`(?m)^\s*Start ip address:\[([^\]]*)\]`)
	reFwMAC    = regexp.MustCompile(`(?m)^\s*MAC Address:\[([^\]]*)\]`)
	reFwMember = regexp.MustCompile(`(?m)^\s*\[(\d+):\]\[(\d+)\]`)
	reFwStatus = regexp.MustCompile(`(?m)^Status\s*:\s*(\w+)`)
	reFwCmt    = regexp.MustCompile(`(?m)^Comments\s*:\s*(.*?)\s*$`)
	reFwSrc    = regexp.MustCompile(`(?m)^Source IP\s*:\s*(.*?)\s*$`)
	reFwAct    = regexp.MustCompile(`(?m)^Pass or Block\s*:\s*(.*?)\s*$`)
	reFwDF     = regexp.MustCompile(`Data Filter:\s*(Enable|Disable)(?:\s*\(Start Filter Set\s*=\s*(\d+)\))?`)
	reFwLimits = regexp.MustCompile(`s: set, range 1-(\d+)\.[\s\S]*?r: rule, range 1-(\d+)\.`)
)

type fwObj struct {
	Name, Type, IP, MAC string
}

func (o fwObj) empty() bool {
	return o.Name == "" && (o.Type == "mask" || o.Type == "") && (o.IP == "" || o.IP == "0.0.0.0") && (o.MAC == "" || o.MAC == zeroMAC)
}

func parseFwObj(s string) (fwObj, bool) {
	var o fwObj
	m := reFwName.FindStringSubmatch(s)
	if m == nil {
		return o, false
	}
	o.Name = strings.TrimSpace(m[1])
	if m := reFwType.FindStringSubmatch(s); m != nil {
		o.Type = strings.ToLower(strings.TrimSpace(m[1]))
	}
	if m := reFwIP.FindStringSubmatch(s); m != nil {
		o.IP = strings.TrimSpace(m[1])
	}
	if m := reFwMAC.FindStringSubmatch(s); m != nil {
		o.MAC = normMAC(m[1])
	}
	return o, true
}

type fwGrp struct {
	Name    string
	Members [fwPerGroup]int
}

func parseFwGrp(s string) (fwGrp, bool) {
	var g fwGrp
	m := reFwName.FindStringSubmatch(s)
	if m == nil {
		return g, false
	}
	g.Name = strings.TrimSpace(m[1])
	for _, x := range reFwMember.FindAllStringSubmatch(s, -1) {
		k, _ := strconv.Atoi(x[1])
		v, _ := strconv.Atoi(x[2])
		if k >= 0 && k < fwPerGroup {
			g.Members[k] = v
		}
	}
	return g, true
}

type fwRule struct {
	On      bool
	Comment string
	Source  string
	Block   bool
}

func (r fwRule) ours() bool { return r.unit() >= 0 }

// unit: which DrayPulse rule this is (-1: not DrayPulse's).
func (r fwRule) unit() int {
	for u, x := range fwUnits {
		if r.Comment == x.Comment {
			return u
		}
	}
	return -1
}

// right: the enabled block rule of unit u, with its second group exactly
// when two says so.
func (r fwRule) right(u int, two bool) bool {
	x := fwUnits[u]
	return r.unit() == u && r.On && r.Block && strings.Contains(r.Source, grpTag(x.G1)) && strings.Contains(r.Source, grpTag(x.G2)) == two
}

// free: an untouched slot (disabled, no comment, any source, default pass).
func (r fwRule) free() bool {
	return !r.On && (r.Comment == "" || r.Comment == "<null>") && r.Source == "Any" && !r.Block
}

func parseFwRule(s string) (fwRule, bool) {
	var r fwRule
	m := reFwStatus.FindStringSubmatch(s)
	if m == nil {
		return r, false
	}
	r.On = strings.EqualFold(m[1], "Enable")
	if m := reFwCmt.FindStringSubmatch(s); m != nil {
		r.Comment = m[1]
	}
	if m := reFwSrc.FindStringSubmatch(s); m != nil {
		r.Source = strings.TrimRight(m[1], ", ")
	}
	if m := reFwAct.FindStringSubmatch(s); m != nil {
		r.Block = strings.HasPrefix(strings.ToLower(m[1]), "block")
	}
	return r, true
}

// ---------- router session helpers ----------

func (o *bindOps) fw(cmd string) (string, error) {
	if !fwCommandAllowed(cmd) {
		return "", fmt.Errorf("lệnh CLI không được phép: %q", cmd)
	}
	out, err := o.cli.runHeld(o.ctx, []string{cmd})
	if o.trace != nil {
		o.trace(cmd, out[cmd], err)
	}
	if err != nil {
		return "", err
	}
	text := out[cmd]
	if strings.HasSuffix(cmd, " -v") || strings.HasSuffix(cmd, " ?") {
		return text, nil
	}
	low := strings.ToLower(text)
	for _, bad := range []string{"unknown command", "command not found", "invalid", "error", "fail", "usage"} {
		if strings.Contains(low, bad) {
			return text, fmt.Errorf("router từ chối lệnh %q: %s", cmd, firstLine(text))
		}
	}
	return text, nil
}

func (o *bindOps) fwObj(i int) (fwObj, error) {
	t, err := o.fw(fmt.Sprintf("object ip obj %d -v", i))
	if err != nil {
		return fwObj{}, err
	}
	ob, ok := parseFwObj(t)
	if !ok {
		return ob, fmt.Errorf("không hiểu kết quả “object ip obj %d -v”: %s", i, rawSnippet(t))
	}
	return ob, nil
}

func (o *bindOps) fwGrp(i int) (fwGrp, error) {
	t, err := o.fw(fmt.Sprintf("object ip grp %d -v", i))
	if err != nil {
		return fwGrp{}, err
	}
	g, ok := parseFwGrp(t)
	if !ok {
		return g, fmt.Errorf("không hiểu kết quả “object ip grp %d -v”: %s", i, rawSnippet(t))
	}
	return g, nil
}

func (o *bindOps) fwRule(s, r int) (fwRule, error) {
	t, err := o.fw(fmt.Sprintf("ipf rule %d %d -v", s, r))
	if err != nil {
		return fwRule{}, err
	}
	x, ok := parseFwRule(t)
	if !ok {
		return x, fmt.Errorf("không hiểu kết quả “ipf rule %d %d -v”: %s", s, r, rawSnippet(t))
	}
	return x, nil
}

// fwDataFilter reads whether the data filter is on and its start set.
func (o *bindOps) fwDataFilter() (on bool, start int, err error) {
	t, err := o.fw("ipf set -v")
	if err != nil {
		return false, 0, err
	}
	m := reFwDF.FindStringSubmatch(t)
	if m == nil {
		return false, 0, fmt.Errorf("không hiểu kết quả “ipf set -v”: %s", rawSnippet(t))
	}
	on = m[1] == "Enable"
	start = 1
	if m[2] != "" {
		start, _ = strconv.Atoi(m[2])
	}
	return on, start, nil
}

// ---------- converging the router to the wanted blocks ----------

// fwWant is one block DrayPulse wants on the router.
type fwWant struct {
	Key string // fwKeyMAC / fwKeyIP
}

// FwReport says what a convergence had to change (for drift events).
type FwReport struct {
	Recreated []string // objects that were missing or wrong
	Removed   []string
	MovedUp   int  // positions the rule was moved above "Pass Immediately" rules
	FilterOn  bool // DrayPulse switched the data filter on
	FilterOff bool
	RuleSet   bool // the rule was (re)written: missing or switched off before
	RulePlace string
}

var errFwFull = fmt.Errorf("đã chặn tối đa %d thiết bị/IP trên router này (DrayPulse dùng 2 luật, %d nhóm IP × %d đối tượng)", fwMax, len(fwGroups), fwPerGroup)

// errFwFilterOff: the data filter is off and the start set holds the admin's
// enabled rules, which switching it on would activate.
type errFwFilterOff struct{ rules []string }

func (e errFwFilterOff) Error() string {
	return "Firewall → Data Filter của router đang TẮT, và bộ luật có luật của bạn đang bật (" + strings.Join(e.rules, "; ") +
		"). Bật Data Filter sẽ áp dụng cả các luật này, nên DrayPulse không tự bật. Hãy kiểm tra các luật đó rồi bật Data Filter trong Firewall → General Setup, sau đó chặn lại"
}

func (h *Hub) fwLoad(routerID int64) fwLayout {
	var l fwLayout
	h.st.GetJSON(fmt.Sprintf("fw:%d", routerID), &l)
	if l.Objects == nil {
		l.Objects = map[string]int{}
	}
	return l
}

func (h *Hub) fwSave(routerID int64, l fwLayout) error {
	return h.st.SetJSON(fmt.Sprintf("fw:%d", routerID), l)
}

// fwApply makes the router block exactly want (and nothing else of
// DrayPulse's), reading every piece back.
func (h *Hub) fwApply(o *bindOps, routerID int64, want []string) (*FwReport, error) {
	rep := &FwReport{}
	if len(want) > fwMax {
		return rep, errFwFull
	}
	lay := h.fwLoad(routerID)
	defer func() { h.fwSave(routerID, lay) }() // the final layout, not this copy
	if lay.Sets == 0 {
		if t, err := o.fw("ipf rule ?"); err == nil {
			if m := reFwLimits.FindStringSubmatch(t); m != nil {
				lay.Sets, _ = strconv.Atoi(m[1])
				lay.Rules, _ = strconv.Atoi(m[2])
			}
		}
		if lay.Sets == 0 || lay.Rules == 0 {
			lay.Sets, lay.Rules = 12, 7
		}
	}
	dfOn, start, err := o.fwDataFilter()
	if err != nil {
		return rep, err
	}
	wanted := map[string]bool{}
	for _, k := range want {
		wanted[k] = true
	}
	// 1. the rule slots: ours if placed, else the first free ones of the set
	set := start
	if !dfOn && lay.Set > 0 {
		set = lay.Set
	}
	need := fwUnitsFor(len(want))
	rules := map[int]fwRule{}
	slots := make([]int, len(fwUnits))
	for r := 1; r <= lay.Rules; r++ {
		x, err := o.fwRule(set, r)
		if err != nil {
			return rep, err
		}
		rules[r] = x
		if u := x.unit(); u >= 0 && slots[u] == 0 {
			slots[u] = r
		}
	}
	taken := func(r int) bool {
		for _, s := range slots {
			if s == r {
				return true
			}
		}
		return false
	}
	for u := 0; u < need; u++ {
		if slots[u] > 0 {
			continue
		}
		for r := 1; r <= lay.Rules; r++ {
			if rules[r].free() && !taken(r) {
				slots[u] = r
				break
			}
		}
		if slots[u] == 0 {
			return rep, fmt.Errorf("bộ luật lọc số %d của router không còn chỗ trống cho luật chặn “%s” của DrayPulse", set, fwUnits[u].Comment)
		}
	}
	if len(want) > 0 && !dfOn {
		var others []string
		for r := 1; r <= lay.Rules; r++ {
			if x := rules[r]; x.On && !x.ours() {
				others = append(others, fmt.Sprintf("luật %d-%d “%s”", set, r, strings.TrimPrefix(x.Comment, "<null>")))
			}
		}
		if len(others) > 0 {
			return rep, errFwFilterOff{others}
		}
	}
	// the groups: one the admin uses is never touched; it stops a block only
	// when DrayPulse needs it (group 31 from the 13th block on, 30 from the
	// 25th, 29 from the 37th)
	grps := map[int]fwGrp{}
	foreign := map[int]bool{}
	for gi, g := range fwGroups {
		cur, err := o.fwGrp(g)
		if err != nil {
			return rep, err
		}
		if cur.Name != "" && cur.Name != fmt.Sprintf("DrayPulse%d", gi+1) {
			if gi*fwPerGroup < len(want) {
				return rep, fmt.Errorf("nhóm IP %d của router đang được dùng (“%s”): DrayPulse cần nhóm %d để chặn quá %d thiết bị/IP", g, cur.Name, g, gi*fwPerGroup)
			}
			foreign[g] = true
		}
		grps[g] = cur
	}
	// 2. switch off a rule no longer needed before its groups shrink
	for u, slot := range slots {
		if slot > 0 && u >= need && rules[slot].unit() == u && rules[slot].On {
			if _, err := o.fw(fmt.Sprintf("ipf rule %d %d -e 0", set, slot)); err != nil {
				return rep, err
			}
			x := rules[slot]
			x.On = false
			rules[slot] = x
		}
	}
	// 3. objects for new blocks (not in any group yet); repaired in place
	used := map[int]bool{}
	var drop []string
	for k, i := range lay.Objects {
		used[i] = true // an unwanted one stays reserved until it left the groups
		if !wanted[k] {
			drop = append(drop, k)
		}
	}
	sort.Strings(drop)
	var keys []string
	for k := range wanted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		i, ok := lay.Objects[k]
		if ok {
			cur, err := o.fwObj(i)
			if err != nil {
				return rep, err
			}
			if fwObjIs(cur, k) {
				continue
			}
			if cur.Name != "" && cur.Name != fwObjName(k) { // taken by the admin meanwhile: find another
				delete(lay.Objects, k)
				delete(used, i)
				ok = false
			}
		}
		if !ok {
			free, err := h.fwFreeObj(o, used)
			if err != nil {
				return rep, err
			}
			i = free
		}
		used[i] = true
		if err := h.fwSetObj(o, i, k); err != nil {
			return rep, err
		}
		lay.Objects[k] = i
		rep.Recreated = append(rep.Recreated, k)
	}
	// 4. groups. An emptied group must never stay a source of an enabled
	// rule, and an object leaves its group before it is cleared.
	var idx []int
	for _, k := range keys {
		idx = append(idx, lay.Objects[k])
	}
	sort.Ints(idx)
	two := func(u int) bool { return len(idx) > u*fwPerRule+fwPerGroup }
	for u := 0; u < need; u++ {
		slot := slots[u]
		x := rules[slot]
		if x.unit() == u && x.On && !two(u) && strings.Contains(x.Source, grpTag(fwUnits[u].G2)) {
			if _, err := o.fw(fmt.Sprintf(`ipf rule %d %d -s "g 2 0"`, set, slot)); err != nil {
				return rep, err
			}
			x.Source = "(g1)IP " + grpTag(fwUnits[u].G1)
			rules[slot] = x
		}
	}
	for gi, g := range fwGroups {
		var mem [fwPerGroup]int
		for k := 0; k < fwPerGroup && gi*fwPerGroup+k < len(idx); k++ {
			mem[k] = idx[gi*fwPerGroup+k]
		}
		cur := grps[g]
		name := fmt.Sprintf("DrayPulse%d", gi+1)
		if foreign[g] || cur.Members == mem && (cur.Name == name || mem == [fwPerGroup]int{}) {
			continue
		}
		if cur.Name != name {
			if _, err := o.fw(fmt.Sprintf("object ip grp %d -n %s", g, name)); err != nil {
				return rep, err
			}
			if _, err := o.fw(fmt.Sprintf("object ip grp %d -i 1", g)); err != nil {
				return rep, err
			}
		}
		if cur.Members != mem {
			parts := make([]string, fwPerGroup)
			for k, v := range mem {
				parts[k] = strconv.Itoa(v)
			}
			if _, err := o.fw(fmt.Sprintf(`object ip grp %d -a "%s"`, g, strings.Join(parts, " "))); err != nil {
				return rep, err
			}
		}
	}
	// 5. objects no longer wanted
	for _, k := range drop {
		if err := h.fwClearObj(o, lay.Objects[k]); err != nil {
			return rep, err
		}
		delete(lay.Objects, k)
		rep.Removed = append(rep.Removed, k)
	}
	lay.Set, lay.Rule, lay.Rule2 = set, slots[0], slots[1]
	if len(want) == 0 {
		if lay.TurnedOn && dfOn {
			others := false
			for r := 1; r <= lay.Rules; r++ {
				if x := rules[r]; x.On && !x.ours() {
					others = true
				}
			}
			if !others {
				if _, err := o.fw("ipf set -d 0"); err != nil {
					return rep, err
				}
				rep.FilterOff = true
			}
			lay.TurnedOn = false
		}
		return rep, h.fwVerify(o, lay, set, slots, nil)
	}
	// 6. the rules: groups first, then the rules (left alone when already
	// right, so a comparison in sync writes nothing)
	for u := 0; u < need; u++ {
		slot, x := slots[u], fwUnits[u]
		cur := rules[slot]
		if cur.right(u, two(u)) {
			continue
		}
		second, src := "0", "(g1)IP "+grpTag(x.G1)
		if two(u) {
			second, src = strconv.Itoa(x.G2), src+", (g2)IP "+grpTag(x.G2)
		}
		g2 := fmt.Sprintf(`ipf rule %d %d -s "g 2 %s"`, set, slot, second)
		// DrayPulse's disabled rule may still name an emptied group: fix it
		// before enabling. (A free rule has no group: the router refuses "g 2 0"
		// on a rule without any object or group.)
		if cur.unit() == u && !cur.On {
			if _, err := o.fw(g2); err != nil {
				return rep, err
			}
		}
		if _, err := o.fw(fmt.Sprintf(`ipf rule %d %d -e 1 -D 0 -s "g 1 %d" -F "1 0" -m "0 0" -M "%s"`, set, slot, x.G1, x.Comment)); err != nil {
			return rep, err
		}
		if _, err := o.fw(g2); err != nil {
			return rep, err
		}
		if cur.unit() != u || !cur.On {
			rep.RuleSet = true
		}
		rules[slot] = fwRule{On: true, Comment: x.Comment, Source: src, Block: true}
	}
	// 7. above every enabled "Pass Immediately" rule of the set, the upper
	// rule first (the lower one then stops right below it at the latest)
	order := make([]int, need)
	for u := range order {
		order[u] = u
	}
	sort.Slice(order, func(a, b int) bool { return slots[order[a]] < slots[order[b]] })
	for _, u := range order {
		slot := slots[u]
		for slot > 1 {
			above := rules[slot-1]
			if !(above.On && !above.Block) {
				// a block rule or a disabled one above: keep looking further up
				passAbove := false
				for r := 1; r < slot; r++ {
					if x := rules[r]; x.On && !x.Block && !x.ours() {
						passAbove = true
					}
				}
				if !passAbove {
					break
				}
			}
			if _, err := o.fw(fmt.Sprintf("ipf rule %d %d -U 0", set, slot)); err != nil {
				return rep, err
			}
			moved, err := o.fwRule(set, slot-1)
			if err != nil {
				return rep, err
			}
			if moved.unit() != u {
				return rep, fmt.Errorf("router không chuyển luật chặn lên trên được (đọc lại luật %d-%d)", set, slot-1)
			}
			if v := above.unit(); v >= 0 { // DrayPulse's other (disabled) rule moves down
				slots[v] = slot
			}
			rules[slot-1], rules[slot] = moved, above
			slot--
			rep.MovedUp++
		}
		slots[u] = slot
	}
	var place []string
	for u := 0; u < need; u++ {
		place = append(place, fmt.Sprintf("%d-%d", set, slots[u]))
	}
	rep.RulePlace = strings.Join(place, ", ")
	lay.Set, lay.Rule, lay.Rule2 = set, slots[0], slots[1]
	if !dfOn {
		if _, err := o.fw(fmt.Sprintf("ipf set -d %d", set)); err != nil {
			return rep, err
		}
		lay.TurnedOn, rep.FilterOn = true, true
	}
	return rep, h.fwVerify(o, lay, set, slots, keys)
}

func fwObjIs(o fwObj, key string) bool {
	if o.Name != fwObjName(key) {
		return false
	}
	if mac, ok := strings.CutPrefix(key, "mac:"); ok {
		return o.Type == "mac" && o.MAC == mac
	}
	return o.IP == strings.TrimPrefix(key, "ip:")
}

func (h *Hub) fwSetObj(o *bindOps, i int, key string) error {
	cmds := []string{fmt.Sprintf("object ip obj %d -n %s", i, fwObjName(key)), fmt.Sprintf("object ip obj %d -i 1", i)}
	if mac, ok := strings.CutPrefix(key, "mac:"); ok {
		cmds = append(cmds, fmt.Sprintf("object ip obj %d -a 4 %s", i, strings.ToLower(mac)))
	} else {
		cmds = append(cmds, fmt.Sprintf("object ip obj %d -a 1 %s", i, strings.TrimPrefix(key, "ip:")))
	}
	for _, c := range cmds {
		if _, err := o.fw(c); err != nil {
			return err
		}
	}
	got, err := o.fwObj(i)
	if err != nil {
		return err
	}
	if !fwObjIs(got, key) {
		return fmt.Errorf("router không lưu đối tượng IP %d cho %s (đọc lại: tên “%s”, kiểu %s, MAC %s, IP %s)", i, strings.SplitN(key, ":", 2)[1], got.Name, got.Type, got.MAC, got.IP)
	}
	return nil
}

func (h *Hub) fwClearObj(o *bindOps, i int) error {
	cur, err := o.fwObj(i)
	if err != nil {
		return err
	}
	if cur.Name != "" && !strings.HasPrefix(cur.Name, "DP-") && !strings.HasPrefix(cur.Name, "DPI") {
		return nil // no longer DrayPulse's: leave it alone
	}
	for _, c := range []string{fmt.Sprintf("object ip obj %d -a 4 00:00:00:00:00:00", i), fmt.Sprintf("object ip obj %d -a 0 0.0.0.0 0.0.0.0", i),
		fmt.Sprintf("object ip obj %d -i 0", i)} {
		if _, err := o.fw(c); err != nil {
			return err
		}
	}
	// a firmware that refuses an empty name keeps "DP-…": still free for
	// DrayPulse (fwFreeObj), harmless for everyone else
	o.fw(fmt.Sprintf(`object ip obj %d -n ""`, i))
	return nil
}

// fwFreeForUs: an empty object, or one of DrayPulse's emptied leftovers.
func fwFreeForUs(o fwObj) bool {
	if o.empty() {
		return true
	}
	ours := strings.HasPrefix(o.Name, "DP-") || strings.HasPrefix(o.Name, "DPI")
	return ours && fwObj{Type: o.Type, IP: o.IP, MAC: o.MAC}.empty()
}

// fwFreeObj finds an empty IP object from index 192 downwards.
func (h *Hub) fwFreeObj(o *bindOps, used map[int]bool) (int, error) {
	for i := fwObjTop; i >= fwObjLow; i-- {
		if used[i] {
			continue
		}
		cur, err := o.fwObj(i)
		if err != nil {
			return 0, err
		}
		if fwFreeForUs(cur) {
			return i, nil
		}
	}
	return 0, fmt.Errorf("router không còn đối tượng IP trống (DrayPulse tìm từ số %d xuống %d)", fwObjTop, fwObjLow)
}

// fwVerify reads the groups and rules back.
func (h *Hub) fwVerify(o *bindOps, lay fwLayout, set int, slots []int, keys []string) error {
	var idx []int
	for _, k := range keys {
		idx = append(idx, lay.Objects[k])
	}
	sort.Ints(idx)
	for gi, g := range fwGroups {
		cur, err := o.fwGrp(g)
		if err != nil {
			return err
		}
		if cur.Name != "" && cur.Name != fmt.Sprintf("DrayPulse%d", gi+1) && gi*fwPerGroup >= len(idx) {
			continue // the admin's group, not needed by DrayPulse
		}
		for k := 0; k < fwPerGroup; k++ {
			want := 0
			if gi*fwPerGroup+k < len(idx) {
				want = idx[gi*fwPerGroup+k]
			}
			if cur.Members[k] != want {
				return fmt.Errorf("router không lưu đúng nhóm IP %d (vị trí %d: %d, cần %d)", g, k, cur.Members[k], want)
			}
		}
	}
	need := fwUnitsFor(len(keys))
	for u, slot := range slots {
		if slot == 0 {
			continue
		}
		r, err := o.fwRule(set, slot)
		if err != nil {
			return err
		}
		switch {
		case r.unit() != u:
			return fmt.Errorf("luật %d-%d không còn là luật “%s” của DrayPulse", set, slot, fwUnits[u].Comment)
		case u < need && !r.right(u, len(idx) > u*fwPerRule+fwPerGroup):
			return fmt.Errorf("router không lưu đúng luật chặn %d-%d (đọc lại: %v, nguồn %s)", set, slot, r.On, r.Source)
		case u >= need && r.On:
			return fmt.Errorf("router chưa tắt luật chặn %d-%d", set, slot)
		}
	}
	return nil
}

// fwWantList: what DrayPulse blocks on a router (devices by MAC, IP-only
// blocks), protected entries excluded.
func (h *Hub) fwWantList(routerID int64, sf blockSafety) ([]string, error) {
	devs, err := h.st.ListDevices(routerID)
	if err != nil {
		return nil, err
	}
	blocks, err := h.st.ListBlocks(routerID)
	if err != nil {
		return nil, err
	}
	var want []string
	for _, d := range devs {
		if !sf.macs[d.MAC] {
			want = append(want, fwKeyMAC(d.MAC))
		}
	}
	for _, b := range blocks {
		if b.MAC == "" && !sf.ips[b.IP] && net.ParseIP(b.IP) != nil {
			want = append(want, fwKeyIP(b.IP))
		}
	}
	return want, nil
}

var errFwNoRouter = errors.New("router không có trong DrayPulse")

// fwCheckResult is a read-only comparison with the router.
type fwCheckResult struct {
	FilterOn, RuleOn bool
	Rule             string
	Missing, Extra   []string
	Others           int // the admin's enabled rules in the same set
}

func (h *Hub) fwCheck(o *bindOps, routerID int64, want []string) (fwCheckResult, error) {
	var res fwCheckResult
	lay := h.fwLoad(routerID)
	dfOn, start, err := o.fwDataFilter()
	if err != nil {
		return res, err
	}
	res.FilterOn = dfOn
	set := start
	if !dfOn && lay.Set > 0 {
		set = lay.Set
	}
	n := lay.Rules
	if n == 0 {
		n = 7
	}
	need, found, ok := fwUnitsFor(len(want)), 0, true
	var places []string
	for r := 1; r <= n; r++ {
		x, err := o.fwRule(set, r)
		if err != nil {
			return res, err
		}
		switch u := x.unit(); {
		case u >= 0:
			if u < need {
				found++
				ok = ok && x.right(u, len(want) > u*fwPerRule+fwPerGroup)
				places = append(places, fmt.Sprintf("%d-%d", set, r))
			}
		case x.On:
			res.Others++
		}
	}
	res.RuleOn = need > 0 && found == need && ok
	res.Rule = strings.Join(places, ", ")
	wanted := map[string]bool{}
	for _, k := range want {
		wanted[k] = true
		i, ok := lay.Objects[k]
		if !ok {
			res.Missing = append(res.Missing, k)
			continue
		}
		cur, err := o.fwObj(i)
		if err != nil {
			return res, err
		}
		if !fwObjIs(cur, k) {
			res.Missing = append(res.Missing, k)
		}
	}
	for k := range lay.Objects {
		if !wanted[k] {
			res.Extra = append(res.Extra, k)
		}
	}
	return res, nil
}

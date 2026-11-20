package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------- Blocking clients by MAC through the DrayTek firewall ----------
//
// The admin builds one firewall rule once in the web UI (Firewall → Filter
// Setup → Set S → Rule R: source = IP group G "DrayPulse", action = Block
// Immediately). DrayPulse then only:
//   - writes the MAC into one of its reserved IP objects (type MAC, name DP-…),
//   - sets the member list of group G,
//   - switches rule R on while at least one client is blocked, off otherwise
//     (an empty group must never be live).
// Every write is read back with "-v" and rolled back if the router does not
// show the expected value. Only the fixed commands in cliWriteAllowed exist.

const zeroMAC = "00:00:00:00:00:00"

var errBlockNotReady = errors.New("chưa bật hoặc chưa kiểm tra cấu hình chặn client (Router → Sửa → Chặn client theo MAC)")

func validBlockCfg(b *BlockCfg) error {
	if !b.Enabled {
		return nil
	}
	switch {
	case b.Set < 1 || b.Set > 12:
		return errors.New("filter set phải từ 1 đến 12")
	case b.Rule < 1 || b.Rule > 7:
		return errors.New("rule phải từ 1 đến 7")
	case b.Group < 1 || b.Group > 32:
		return errors.New("IP group phải từ 1 đến 32")
	case b.ObjFrom < 1 || b.ObjTo > 192 || b.ObjFrom > b.ObjTo:
		return errors.New("khoảng IP object phải nằm trong 1–192")
	case b.ObjTo-b.ObjFrom+1 > 12:
		return errors.New("tối đa 12 IP object (một IP group chứa được 12 object)")
	}
	return nil
}

// sameBlockSlots tells whether two configs point at the same router resources.
func sameBlockSlots(a, b BlockCfg) bool {
	return a.Enabled == b.Enabled && a.Set == b.Set && a.Rule == b.Rule && a.Group == b.Group && a.ObjFrom == b.ObjFrom && a.ObjTo == b.ObjTo
}

func dpObjName(mac string) string {
	return "DP-" + strings.ToUpper(strings.ReplaceAll(mac, ":", ""))[6:]
}

// blockCLI returns the router's CLI client: the running poller's session when
// there is one (DrayOS allows few CLI logins), otherwise a fresh one.
func (h *Hub) blockCLI(rs *RState) (*cliClient, func(), error) {
	rs.mu.RLock()
	src, cfg := rs.src, rs.cfg
	rs.mu.RUnlock()
	if d := asDraytek(src); d != nil && d.cli != nil {
		return d.cli, func() {}, nil
	}
	s, err := h.source(&cfg)
	if err != nil {
		return nil, nil, err
	}
	d := asDraytek(s)
	if d == nil || d.cli == nil {
		return nil, nil, errors.New("chặn client cần bật Telnet/SSH cho router này")
	}
	return d.cli, d.Close, nil
}

func asDraytek(s Source) *draytekSource {
	switch t := s.(type) {
	case *draytekSource:
		return t
	case *demoSource:
		return t.draytekSource
	}
	return nil
}

type blockOps struct {
	cli *cliClient
	cfg BlockCfg
	ctx context.Context
}

func (o *blockOps) one(cmd string) (string, error) {
	out, err := o.cli.RunWrite(o.ctx, cmd)
	if err != nil {
		return "", err
	}
	text := out[cmd]
	low := strings.ToLower(text)
	if strings.Contains(low, "unknown command") || strings.Contains(low, "command not found") || strings.Contains(low, "invalid") || strings.Contains(low, "error") {
		return text, fmt.Errorf("router từ chối lệnh %q: %s", cmd, firstLine(text))
	}
	return text, nil
}

func (o *blockOps) object(i int) (Row, error) {
	t, err := o.one(fmt.Sprintf("object ip obj %d -v", i))
	if err != nil {
		return nil, err
	}
	return parseIPObject(t), nil
}

func (o *blockOps) group() (string, []int, error) {
	t, err := o.one(fmt.Sprintf("object ip grp %d -v", o.cfg.Group))
	if err != nil {
		return "", nil, err
	}
	n, m := parseIPGroup(t)
	return n, m, nil
}

func (o *blockOps) rule() (Row, error) {
	t, err := o.one(fmt.Sprintf("ipf rule %d %d -v", o.cfg.Set, o.cfg.Rule))
	if err != nil {
		return nil, err
	}
	return parseFilterRule(t), nil
}

func ruleEnabled(r Row) bool { return strings.HasPrefix(r["status"], "enable") }

func sameMembers(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]int{}, a...), append([]int{}, b...)
	sort.Ints(x)
	sort.Ints(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func (o *blockOps) setGroup(members []int) error {
	parts := make([]string, len(members))
	for i, m := range members {
		parts[i] = strconv.Itoa(m)
	}
	if _, err := o.one(fmt.Sprintf("object ip grp %d -a %s", o.cfg.Group, strings.Join(parts, " "))); err != nil {
		return err
	}
	_, got, err := o.group()
	if err != nil {
		return err
	}
	if !sameMembers(got, members) {
		return fmt.Errorf("IP group %d trên router là %v, không khớp %v", o.cfg.Group, got, members)
	}
	return nil
}

func (o *blockOps) setRule(on bool) error {
	v := map[bool]string{true: "1", false: "0"}[on]
	if _, err := o.one(fmt.Sprintf("ipf rule %d %d -e %s", o.cfg.Set, o.cfg.Rule, v)); err != nil {
		return err
	}
	r, err := o.rule()
	if err != nil {
		return err
	}
	if ruleEnabled(r) != on {
		return fmt.Errorf("rule %d/%d không chuyển sang trạng thái %v (router báo %q)", o.cfg.Set, o.cfg.Rule, on, r["status"])
	}
	return nil
}

// setObject writes a MAC into a DrayPulse object and verifies it.
func (o *blockOps) setObject(i int, name, mac string) error {
	for _, c := range []string{fmt.Sprintf("object ip obj %d -n %s", i, name), fmt.Sprintf("object ip obj %d -i 1", i), fmt.Sprintf("object ip obj %d -a 4 %s", i, strings.ToLower(mac))} {
		if _, err := o.one(c); err != nil {
			return err
		}
	}
	got, err := o.object(i)
	if err != nil {
		return err
	}
	if got["mac"] != strings.ToUpper(mac) {
		return fmt.Errorf("IP object %d trên router có MAC %q, không phải %s (firmware có thể không hỗ trợ object loại MAC qua Telnet)", i, got["mac"], mac)
	}
	return nil
}

// ---------- readiness check ----------

type BlockCheck struct {
	OK       bool     `json:"ok"`
	Problems []string `json:"problems"`
	Notes    []string `json:"notes"`
	Rule     Row      `json:"rule,omitempty"`
}

// CheckBlocking verifies the reserved slots and prepares the IP group. It
// writes only the group's name/interface, and only when the group is empty
// or already DrayPulse's.
func (h *Hub) CheckBlocking(ctx context.Context, routerID int64) (*BlockCheck, error) {
	rs := h.get(routerID)
	if rs == nil {
		return nil, ErrNotFound
	}
	rs.blockMu.Lock()
	defer rs.blockMu.Unlock()
	rs.mu.RLock()
	cfg := rs.cfg
	rs.mu.RUnlock()
	bc := cfg.Opts.Block
	if !bc.Enabled {
		return nil, errors.New("chưa bật chặn client cho router này")
	}
	cli, done, err := h.blockCLI(rs)
	if err != nil {
		return nil, err
	}
	defer done()
	o := &blockOps{cli: cli, cfg: bc, ctx: ctx}
	res := &BlockCheck{Problems: []string{}, Notes: []string{}}
	blocks, _ := h.st.ListBlocks(routerID)
	ours := map[int]bool{}
	for _, b := range blocks {
		ours[b.Obj] = true
	}

	// 1. the group: empty or ours
	name, members, err := o.group()
	if err != nil {
		return nil, err
	}
	switch {
	case name == "DrayPulse":
	case name == "" && len(members) == 0:
		for _, c := range []string{fmt.Sprintf("object ip grp %d -n DrayPulse", bc.Group), fmt.Sprintf("object ip grp %d -i 1", bc.Group)} {
			if _, err := o.one(c); err != nil {
				return nil, err
			}
		}
		if n, _, err := o.group(); err != nil || n != "DrayPulse" {
			res.Problems = append(res.Problems, fmt.Sprintf("Không đặt được tên IP group %d thành “DrayPulse” (router báo %q).", bc.Group, n))
		} else {
			res.Notes = append(res.Notes, fmt.Sprintf("Đã đặt tên IP group %d là “DrayPulse”.", bc.Group))
		}
	default:
		res.Problems = append(res.Problems, fmt.Sprintf("IP group %d đang được dùng (tên %q, %d object). Chọn group trống khác.", bc.Group, name, len(members)))
	}
	for _, m := range members {
		if m < bc.ObjFrom || m > bc.ObjTo {
			res.Problems = append(res.Problems, fmt.Sprintf("IP group %d chứa object %d nằm ngoài khoảng dành cho DrayPulse.", bc.Group, m))
		}
	}
	// 2. the objects: empty, or DrayPulse's own
	free := 0
	for i := bc.ObjFrom; i <= bc.ObjTo; i++ {
		obj, err := o.object(i)
		if err != nil {
			return nil, err
		}
		n := obj["name"]
		switch {
		case strings.HasPrefix(n, "DP-") || ours[i]:
			if !ours[i] {
				free++
			}
		case n == "":
			free++
		default:
			res.Problems = append(res.Problems, fmt.Sprintf("IP object %d đang được dùng (tên %q).", i, n))
		}
	}
	res.Notes = append(res.Notes, fmt.Sprintf("Còn %d IP object trống để chặn thêm client.", free))
	// 3. the rule the admin built
	rule, err := o.rule()
	if err != nil {
		return nil, err
	}
	res.Rule = rule
	src := strings.ToLower(rule["source"])
	switch {
	case !strings.Contains(strings.ToLower(rule["action"]), "block"):
		res.Problems = append(res.Problems, fmt.Sprintf("Rule %d của filter set %d chưa đặt hành động Block Immediately (đang là %q).", bc.Rule, bc.Set, rule["action"]))
	case !strings.Contains(src, "draypulse") && !strings.Contains(src, "group"):
		res.Problems = append(res.Problems, fmt.Sprintf("Nguồn (Source IP) của rule %d/%d chưa phải IP group “DrayPulse” (đang là %q).", bc.Set, bc.Rule, rule["source"]))
	case strings.EqualFold(rule["source"], "any"):
		res.Problems = append(res.Problems, "Nguồn của rule đang là Any: bật rule sẽ chặn cả mạng.")
	}
	if !strings.Contains(rule["direction"], "-> WAN") && !strings.Contains(rule["direction"], "->WAN") {
		res.Notes = append(res.Notes, "Hướng rule: "+rule["direction"]+" (khuyên dùng LAN/DMZ/RT/VPN -> WAN để chặn ra Internet).")
	}
	if len(blocks) == 0 && ruleEnabled(rule) && len(res.Problems) == 0 {
		if err := o.setRule(false); err != nil {
			res.Problems = append(res.Problems, "Rule đang bật khi chưa chặn ai và không tắt được: "+err.Error())
		} else {
			res.Notes = append(res.Notes, "Đã tắt rule vì chưa có client nào bị chặn.")
		}
	}
	res.OK = len(res.Problems) == 0
	if err := h.setBlockReady(rs, res.OK); err != nil {
		return nil, err
	}
	return res, nil
}

func (h *Hub) setBlockReady(rs *RState, ready bool) error {
	rs.mu.RLock()
	id := rs.cfg.ID
	rs.mu.RUnlock()
	r, err := h.st.GetRouter(id)
	if err != nil {
		return err
	}
	if r.Opts.Block.Ready == ready {
		return nil
	}
	r.Opts.Block.Ready = ready
	if err := h.st.SaveRouter(r); err != nil {
		return err
	}
	rs.mu.Lock()
	rs.cfg.Opts.Block.Ready = ready
	rs.mu.Unlock()
	return nil
}

// ---------- block / unblock ----------

func (h *Hub) blockPrep(routerID int64) (*RState, BlockCfg, error) {
	rs := h.get(routerID)
	if rs == nil {
		return nil, BlockCfg{}, ErrNotFound
	}
	rs.mu.RLock()
	bc := rs.cfg.Opts.Block
	rs.mu.RUnlock()
	if !bc.Enabled || !bc.Ready {
		return nil, bc, errBlockNotReady
	}
	return rs, bc, nil
}

// BlockClient blocks a MAC; on any failure the router is put back as it was.
func (h *Hub) BlockClient(ctx context.Context, routerID int64, mac, ip, name, note, by string) (*Block, error) {
	mac = normMAC(mac)
	if mac == "" || mac == zeroMAC || mac == "FF:FF:FF:FF:FF:FF" {
		return nil, errors.New("địa chỉ MAC không hợp lệ")
	}
	rs, bc, err := h.blockPrep(routerID)
	if err != nil {
		return nil, err
	}
	rs.blockMu.Lock()
	defer rs.blockMu.Unlock()
	blocks, err := h.st.ListBlocks(routerID)
	if err != nil {
		return nil, err
	}
	used := map[int]bool{}
	for _, b := range blocks {
		if b.MAC == mac {
			return nil, errors.New("client này đã bị chặn")
		}
		used[b.Obj] = true
	}
	cli, done, err := h.blockCLI(rs)
	if err != nil {
		return nil, err
	}
	defer done()
	o := &blockOps{cli: cli, cfg: bc, ctx: ctx}

	gname, before, err := o.group()
	if err != nil {
		return nil, err
	}
	if gname != "DrayPulse" {
		return nil, fmt.Errorf("IP group %d không còn là của DrayPulse (tên %q): bấm “Kiểm tra cấu hình” lại", bc.Group, gname)
	}
	rule, err := o.rule()
	if err != nil {
		return nil, err
	}
	if !strings.Contains(strings.ToLower(rule["action"]), "block") {
		return nil, fmt.Errorf("rule %d/%d không còn là Block: bấm “Kiểm tra cấu hình” lại", bc.Set, bc.Rule)
	}
	// pick a free object: not used by a block, and empty or DrayPulse-named on the router
	obj := 0
	for i := bc.ObjFrom; i <= bc.ObjTo && obj == 0; i++ {
		if used[i] {
			continue
		}
		cur, err := o.object(i)
		if err != nil {
			return nil, err
		}
		if cur["name"] == "" || strings.HasPrefix(cur["name"], "DP-") {
			obj = i
		}
	}
	if obj == 0 {
		return nil, fmt.Errorf("hết IP object dành cho DrayPulse (%d–%d): bỏ chặn bớt hoặc mở rộng khoảng", bc.ObjFrom, bc.ObjTo)
	}
	neutral := func() { o.setObject(obj, "DP-free", zeroMAC) }
	if err := o.setObject(obj, dpObjName(mac), mac); err != nil {
		neutral()
		return nil, err
	}
	members := []int{}
	for _, b := range blocks {
		members = append(members, b.Obj)
	}
	members = append(members, obj)
	if err := o.setGroup(members); err != nil {
		if len(before) > 0 {
			o.setGroup(before)
		}
		neutral()
		return nil, err
	}
	if !ruleEnabled(rule) {
		if err := o.setRule(true); err != nil {
			o.setRule(false)
			if len(before) > 0 {
				o.setGroup(before)
			}
			neutral()
			return nil, err
		}
	}
	b := Block{MAC: mac, Obj: obj, IP: ip, Name: name, Note: note, ByUser: by, At: nowMs()}
	if err := h.st.AddBlock(routerID, b); err != nil {
		return nil, err
	}
	label := firstNonEmpty(name, ip, mac)
	var eff effects
	eff.add(nowMs(), "warning", "⛔", fmt.Sprintf("Đã chặn client %s (%s) ra Internet – bởi %s", label, mac, by), false)
	rs.mu.RLock()
	cfg := rs.cfg
	rs.mu.RUnlock()
	h.apply(cfg, eff)
	return &b, nil
}

// UnblockClient removes a MAC. The rule goes off before the group is emptied.
func (h *Hub) UnblockClient(ctx context.Context, routerID int64, mac, by string) error {
	mac = normMAC(mac)
	rs, bc, err := h.blockPrep(routerID)
	if err != nil {
		return err
	}
	rs.blockMu.Lock()
	defer rs.blockMu.Unlock()
	blocks, err := h.st.ListBlocks(routerID)
	if err != nil {
		return err
	}
	var target *Block
	var rest []int
	for i := range blocks {
		if blocks[i].MAC == mac {
			target = &blocks[i]
		} else {
			rest = append(rest, blocks[i].Obj)
		}
	}
	if target == nil {
		return errors.New("client này không bị chặn")
	}
	cli, done, err := h.blockCLI(rs)
	if err != nil {
		return err
	}
	defer done()
	o := &blockOps{cli: cli, cfg: bc, ctx: ctx}
	if len(rest) == 0 {
		if err := o.setRule(false); err != nil {
			return err
		}
	} else if err := o.setGroup(rest); err != nil {
		return err
	}
	// the object is no longer referenced (or the rule is off): blank its MAC
	if err := o.setObject(target.Obj, "DP-free", zeroMAC); err != nil {
		return err
	}
	if err := h.st.DeleteBlock(routerID, mac); err != nil {
		return err
	}
	var eff effects
	eff.add(nowMs(), "info", "✅", fmt.Sprintf("Đã bỏ chặn client %s (%s) – bởi %s", firstNonEmpty(target.Name, target.IP, mac), mac, by), false)
	rs.mu.RLock()
	cfg := rs.cfg
	rs.mu.RUnlock()
	h.apply(cfg, eff)
	return nil
}

// BlockInfo is the blocking summary shown with a router.
type BlockInfo struct {
	Ready  bool    `json:"ready"`
	Set    int     `json:"set"`
	Rule   int     `json:"rule"`
	Group  int     `json:"group"`
	Blocks []Block `json:"blocks"`
}

// BlockStatus compares DrayPulse's list with the router (read-only).
type BlockStatus struct {
	Blocks      []Block `json:"blocks"`
	RuleEnabled *bool   `json:"ruleEnabled"`
	Members     []int   `json:"members"`
	Drift       string  `json:"drift,omitempty"`
}

func (h *Hub) BlockState(ctx context.Context, routerID int64, live bool) (*BlockStatus, error) {
	blocks, err := h.st.ListBlocks(routerID)
	if err != nil {
		return nil, err
	}
	st := &BlockStatus{Blocks: blocks, Members: []int{}}
	if !live {
		return st, nil
	}
	rs, bc, err := h.blockPrep(routerID)
	if err != nil {
		return st, nil
	}
	rs.blockMu.Lock()
	defer rs.blockMu.Unlock()
	cli, done, err := h.blockCLI(rs)
	if err != nil {
		return nil, err
	}
	defer done()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	o := &blockOps{cli: cli, cfg: bc, ctx: cctx}
	_, members, err := o.group()
	if err != nil {
		return nil, err
	}
	rule, err := o.rule()
	if err != nil {
		return nil, err
	}
	on := ruleEnabled(rule)
	st.RuleEnabled, st.Members = &on, members
	want := []int{}
	for _, b := range blocks {
		want = append(want, b.Obj)
	}
	switch {
	case len(blocks) > 0 && !on:
		st.Drift = "Rule chặn trên router đang TẮT dù DrayPulse còn client bị chặn."
	case len(blocks) == 0 && on:
		st.Drift = "Rule chặn trên router đang BẬT dù không có client nào bị chặn."
	case len(blocks) > 0 && !sameMembers(members, want):
		st.Drift = fmt.Sprintf("IP group trên router (%v) khác danh sách của DrayPulse (%v).", members, want)
	}
	return st, nil
}

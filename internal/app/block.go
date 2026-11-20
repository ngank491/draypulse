package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

// ---------- Blocking a client IP with DrayOS "Bind IP to MAC" ----------
//
// DrayOS checks every LAN IP listed in its Bind IP to MAC table: traffic from
// that IP with any other MAC is refused by the router. DrayPulse blocks an IP
// by binding it to a MAC that does not exist (blockMAC), using only the
// documented commands:
//
//	ip bindmac show | on | off | add <IP> <MAC> <comment> | del <IP>
//
// Nothing has to be prepared on the router. DrayPulse's entries carry the
// comment "DrayPulse"; it never edits or deletes other entries. Non-strict
// mode ("on") is used, so IPs that are not in the table keep working. Every
// change is read back with "ip bindmac show" and undone on mismatch.

// blockMAC is a locally administered address no real device uses.
const blockMAC = "02:DD:00:00:00:01"
const blockComment = "DrayPulse"

var errBlockOff = errors.New("chưa bật chặn client cho router này (Router → Sửa → Chặn client)")

type bindEntry struct {
	IP, MAC, Comment string
}

type bindState struct {
	On, Strict bool
	Known      bool // the on/off line was found
	Entries    []bindEntry
}

func (s bindState) find(ip string) *bindEntry {
	for i := range s.Entries {
		if s.Entries[i].IP == ip {
			return &s.Entries[i]
		}
	}
	return nil
}

func (e bindEntry) ours() bool {
	return e.MAC == blockMAC && strings.EqualFold(e.Comment, blockComment)
}

var (
	reBindOn    = regexp.MustCompile(`(?i)bind mac function is (?:turned )?(ON|OFF)`)
	reBindStr   = regexp.MustCompile(`(?i)bind mac function is STRICT (ON|OFF)`)
	reBindEntry = regexp.MustCompile(`(?i)IP\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+bind MAC\s*:\s*([0-9a-f]{2}(?:[-:][0-9a-f]{2}){5})`)
	reBindCmt   = regexp.MustCompile(`(?i)^\s*Comment\s*:\s*(\S*)`)
)

// parseBindMAC reads "ip bindmac show":
//
//	ip bind mac function is turned OFF
//	ip bind mac function is STRICT OFF
//	Show all IP Bind MAC entries.
//	IP : 192.168.1.46 bind MAC : 00-50-7f-22-33-55 HOST ID :
//	Comment : just
func parseBindMAC(s string) bindState {
	var st bindState
	for _, m := range reBindOn.FindAllStringSubmatch(s, -1) {
		st.On, st.Known = strings.EqualFold(m[1], "ON"), true
	}
	if m := reBindStr.FindStringSubmatch(s); m != nil {
		st.Strict = strings.EqualFold(m[1], "ON")
	}
	for _, line := range strings.Split(s, "\n") {
		if m := reBindEntry.FindStringSubmatch(line); m != nil {
			st.Entries = append(st.Entries, bindEntry{IP: m[1], MAC: dashMAC(m[2])})
			continue
		}
		if m := reBindCmt.FindStringSubmatch(line); m != nil && len(st.Entries) > 0 {
			st.Entries[len(st.Entries)-1].Comment = m[1]
		}
	}
	return st
}

// BlockCfg turns IP blocking on for a router. TurnedOn remembers that
// DrayPulse switched Bind IP to MAC on, so it can switch it off again.
type BlockCfg struct {
	Enabled  bool `json:"enabled"`
	TurnedOn bool `json:"turnedOn"`
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

type bindOps struct {
	cli *cliClient
	ctx context.Context
}

func (o *bindOps) run(cmd string) (string, error) {
	out, err := o.cli.RunWrite(o.ctx, cmd)
	if err != nil {
		return "", err
	}
	text := out[cmd]
	low := strings.ToLower(text)
	for _, bad := range []string{"unknown command", "command not found", "invalid", "error", "fail"} {
		if strings.Contains(low, bad) {
			return text, fmt.Errorf("router từ chối lệnh %q: %s", cmd, firstLine(text))
		}
	}
	return text, nil
}

func (o *bindOps) show() (bindState, error) {
	t, err := o.run("ip bindmac show")
	if err != nil {
		return bindState{}, err
	}
	st := parseBindMAC(t)
	if !st.Known {
		return st, fmt.Errorf("không đọc được trạng thái Bind IP to MAC (router trả về: %s)", firstLine(t))
	}
	return st, nil
}

func (o *bindOps) setOn(on bool) error {
	cmd := map[bool]string{true: "ip bindmac on", false: "ip bindmac off"}[on]
	if _, err := o.run(cmd); err != nil {
		return err
	}
	st, err := o.show()
	if err != nil {
		return err
	}
	if st.On != on {
		return fmt.Errorf("router không chuyển Bind IP to MAC sang %v", map[bool]string{true: "ON", false: "OFF"}[on])
	}
	return nil
}

// checkBlockTarget refuses addresses whose blocking would cut off the network:
// the router itself, gateways, DrayPulse's own host, or anything outside the LAN.
func (h *Hub) checkBlockTarget(rs *RState, ip string) error {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return errors.New("địa chỉ IPv4 không hợp lệ")
	}
	if !a.IsPrivate() {
		return errors.New("chỉ chặn được IP trong mạng LAN (địa chỉ riêng)")
	}
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	inLAN := false
	for _, r := range rs.Sections["address"] {
		if strings.SplitN(r["address"], "/", 2)[0] == ip {
			return errors.New("đây là địa chỉ của chính router")
		}
		if p, err := netip.ParsePrefix(r["address"]); err == nil && p.Masked().Contains(a) && p.Bits() < 32 {
			inLAN = true
		}
	}
	for _, l := range rs.Sections["lan"] {
		if l["gateway"] == ip || l["address"] == ip {
			return errors.New("đây là gateway của một mạng LAN")
		}
		if l["network"] != "" && inNetwork(ip, l["network"]) {
			inLAN = true
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, x := range addrs {
			if n, ok := x.(*net.IPNet); ok && n.IP.String() == ip {
				return errors.New("đây là máy đang chạy DrayPulse: chặn sẽ mất kết nối giám sát")
			}
		}
	}
	if !inLAN && (len(rs.Sections["address"]) > 0 || len(rs.Sections["lan"]) > 0) {
		return errors.New("IP không thuộc mạng LAN nào của router này")
	}
	return nil
}

func (h *Hub) blockPrep(routerID int64) (*RState, Router, error) {
	rs := h.get(routerID)
	if rs == nil {
		return nil, Router{}, ErrNotFound
	}
	rs.mu.RLock()
	cfg := rs.cfg
	rs.mu.RUnlock()
	if !cfg.Opts.Block.Enabled {
		return nil, cfg, errBlockOff
	}
	return rs, cfg, nil
}

func (h *Hub) saveTurnedOn(rs *RState, v bool) error {
	rs.mu.RLock()
	id := rs.cfg.ID
	rs.mu.RUnlock()
	r, err := h.st.GetRouter(id)
	if err != nil {
		return err
	}
	r.Opts.Block.TurnedOn = v
	if err := h.st.SaveRouter(r); err != nil {
		return err
	}
	rs.mu.Lock()
	rs.cfg.Opts.Block.TurnedOn = v
	rs.mu.Unlock()
	return nil
}

// BlockClient blocks an IP; on any failure the router is put back as it was.
func (h *Hub) BlockClient(ctx context.Context, routerID int64, ip, mac, name, note, by string) (*Block, error) {
	ip = strings.TrimSpace(ip)
	rs, cfg, err := h.blockPrep(routerID)
	if err != nil {
		return nil, err
	}
	if err := h.checkBlockTarget(rs, ip); err != nil {
		return nil, err
	}
	rs.blockMu.Lock()
	defer rs.blockMu.Unlock()
	blocks, err := h.st.ListBlocks(routerID)
	if err != nil {
		return nil, err
	}
	for _, b := range blocks {
		if b.IP == ip {
			return nil, errors.New("IP này đã bị chặn")
		}
	}
	cli, done, err := h.blockCLI(rs)
	if err != nil {
		return nil, err
	}
	defer done()
	o := &bindOps{cli: cli, ctx: ctx}
	st, err := o.show()
	if err != nil {
		return nil, err
	}
	if e := st.find(ip); e != nil && !e.ours() {
		return nil, fmt.Errorf("IP %s đã có trong bảng Bind IP to MAC của router (gắn với %s): DrayPulse không sửa mục do bạn tạo", ip, e.MAC)
	}
	if !st.On {
		var others []string
		for _, e := range st.Entries {
			if !e.ours() {
				others = append(others, e.IP)
			}
		}
		if len(others) > 0 {
			return nil, fmt.Errorf("Bind IP to MAC đang TẮT nhưng bảng có %d mục do bạn tạo (%s). Bật chức năng sẽ áp dụng cả các mục này, nên DrayPulse không tự bật. Hãy kiểm tra/xoá các mục đó trong LAN → Bind IP to MAC rồi thử lại", len(others), strings.Join(others, ", "))
		}
	}
	turnedOn := false
	undo := func() {
		o.run("ip bindmac del " + ip)
		if turnedOn {
			o.setOn(false)
		}
	}
	if st.find(ip) == nil {
		if _, err := o.run(fmt.Sprintf("ip bindmac add %s %s %s", ip, strings.ToLower(blockMAC), blockComment)); err != nil {
			undo()
			return nil, err
		}
	}
	if !st.On {
		if err := o.setOn(true); err != nil {
			undo()
			return nil, err
		}
		turnedOn = true
	}
	after, err := o.show()
	if err != nil {
		undo()
		return nil, err
	}
	if e := after.find(ip); e == nil || e.MAC != blockMAC || !after.On {
		undo()
		return nil, fmt.Errorf("router không lưu mục chặn cho %s (đọc lại không thấy IP này gắn với MAC chặn)", ip)
	}
	if turnedOn {
		if err := h.saveTurnedOn(rs, true); err != nil {
			return nil, err
		}
	}
	b := Block{IP: ip, MAC: normMAC(mac), Name: name, Note: note, ByUser: by, At: nowMs()}
	if err := h.st.AddBlock(routerID, b); err != nil {
		return nil, err
	}
	var eff effects
	eff.add(nowMs(), "warning", "⛔", fmt.Sprintf("Đã chặn %s khỏi mạng – bởi %s", blockLabel(b), by), false)
	h.apply(cfg, eff)
	return &b, nil
}

func blockLabel(b Block) string {
	if b.Name != "" {
		return b.Name + " (" + b.IP + ")"
	}
	return b.IP
}

// UnblockClient removes DrayPulse's entry for an IP. When no entries are
// left and DrayPulse had switched the function on, it switches it off again.
func (h *Hub) UnblockClient(ctx context.Context, routerID int64, ip, by string) error {
	rs, cfg, err := h.blockPrep(routerID)
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
	for i := range blocks {
		if blocks[i].IP == ip {
			target = &blocks[i]
		}
	}
	if target == nil {
		return errors.New("IP này không bị chặn")
	}
	cli, done, err := h.blockCLI(rs)
	if err != nil {
		return err
	}
	defer done()
	o := &bindOps{cli: cli, ctx: ctx}
	st, err := o.show()
	if err != nil {
		return err
	}
	if e := st.find(ip); e != nil {
		if !e.ours() {
			return fmt.Errorf("mục %s trong Bind IP to MAC không còn là của DrayPulse (MAC %s): kiểm tra trên router", ip, e.MAC)
		}
		if _, err := o.run("ip bindmac del " + ip); err != nil {
			return err
		}
		if st, err = o.show(); err != nil {
			return err
		}
		if st.find(ip) != nil {
			return fmt.Errorf("router vẫn còn mục chặn %s sau khi xoá", ip)
		}
	}
	rs.mu.RLock()
	turnedOn := rs.cfg.Opts.Block.TurnedOn
	rs.mu.RUnlock()
	if turnedOn && len(st.Entries) == 0 && st.On {
		if err := o.setOn(false); err != nil {
			return err
		}
		if err := h.saveTurnedOn(rs, false); err != nil {
			return err
		}
	}
	if err := h.st.DeleteBlock(routerID, ip); err != nil {
		return err
	}
	var eff effects
	eff.add(nowMs(), "info", "✅", fmt.Sprintf("Đã bỏ chặn %s – bởi %s", blockLabel(*target), by), false)
	h.apply(cfg, eff)
	return nil
}

// BlockInfo is the blocking summary shown with a router.
type BlockInfo struct {
	Blocks []Block `json:"blocks"`
}

// BlockStatus compares DrayPulse's list with the router (read-only).
type BlockStatus struct {
	Blocks  []Block  `json:"blocks"`
	On      *bool    `json:"on"`
	Strict  bool     `json:"strict"`
	Missing []string `json:"missing"` // blocked here, not on the router
	Extra   []string `json:"extra"`   // DrayPulse entries on the router not known here
	Others  int      `json:"others"`  // entries created by someone else
}

func (h *Hub) BlockState(ctx context.Context, routerID int64, live bool) (*BlockStatus, error) {
	blocks, err := h.st.ListBlocks(routerID)
	if err != nil {
		return nil, err
	}
	out := &BlockStatus{Blocks: blocks, Missing: []string{}, Extra: []string{}}
	if !live {
		return out, nil
	}
	rs, _, err := h.blockPrep(routerID)
	if err != nil {
		return out, nil
	}
	rs.blockMu.Lock()
	defer rs.blockMu.Unlock()
	cli, done, err := h.blockCLI(rs)
	if err != nil {
		return nil, err
	}
	defer done()
	st, err := (&bindOps{cli: cli, ctx: ctx}).show()
	if err != nil {
		return nil, err
	}
	on := st.On
	out.On, out.Strict = &on, st.Strict
	known := map[string]bool{}
	for _, b := range blocks {
		known[b.IP] = true
		if e := st.find(b.IP); e == nil || !e.ours() {
			out.Missing = append(out.Missing, b.IP)
		}
	}
	for _, e := range st.Entries {
		switch {
		case e.ours() && !known[e.IP]:
			out.Extra = append(out.Extra, e.IP)
		case !e.ours():
			out.Others++
		}
	}
	return out, nil
}

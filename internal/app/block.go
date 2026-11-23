package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
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
const zeroMAC = "00:00:00:00:00:00"

var errBlockOff = errors.New("chưa bật chặn client cho router này (Router → Sửa → Chặn client)")

type bindEntry struct {
	IP, MAC, Comment string
}

type bindState struct {
	On, Strict bool
	Known      bool // the on/off line was found
	Blank      bool // the router printed nothing (some firmware lists entries only)
	Entries    []bindEntry
	Raw        string
}

func (s bindState) find(ip string) *bindEntry {
	for i := range s.Entries {
		if s.Entries[i].IP == ip {
			return &s.Entries[i]
		}
	}
	return nil
}

// ours: DrayPulse's entries carry the blocking MAC (no real device uses it)
// and, when the firmware shows it, the comment "DrayPulse".
func (e bindEntry) ours() bool {
	return e.MAC == blockMAC && (e.Comment == "" || strings.EqualFold(e.Comment, blockComment))
}

var (
	reBindOn    = regexp.MustCompile(`(?i)bind mac function is (?:turned )?(ON|OFF)`)
	reBindStr   = regexp.MustCompile(`(?i)bind mac function is STRICT (ON|OFF)`)
	reBindEntry = regexp.MustCompile(`(?i)IP\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+bind MAC\s*:\s*([0-9a-f]{2}(?:[-:][0-9a-f]{2}){5})`)
	reBindCmt   = regexp.MustCompile(`(?i)^\s*Comment\s*:\s*(\S*)`)
	reBindCmtIn = regexp.MustCompile(`(?i)\bComment\s*:\s*(\S*)`)
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
		// Vigor 3912S (4.4.3.2) prints everything on one line:
		//   IP : 192.168.31.246 bind MAC : 02-dd-00-00-00-01 HOST ID : Comment : DrayPulse
		// the user guide shows "Comment : …" on the next line. Accept both.
		if loc := reBindEntry.FindStringSubmatchIndex(line); loc != nil {
			e := bindEntry{IP: line[loc[2]:loc[3]], MAC: dashMAC(line[loc[4]:loc[5]])}
			if m := reBindCmtIn.FindStringSubmatch(line[loc[1]:]); m != nil {
				e.Comment = m[1]
			}
			st.Entries = append(st.Entries, e)
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
// AutoPaused stops automatic blocking after the safety limit was hit, until
// an admin resumes it.
type BlockCfg struct {
	Enabled      bool  `json:"enabled"`
	TurnedOn     bool  `json:"turnedOn"`
	AutoPaused   bool  `json:"autoPaused,omitempty"`
	AutoPausedAt int64 `json:"autoPausedAt,omitempty"`
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

// sharedCLI lends the running poller's CLI client to d when both log in to
// the same router the same way: DrayOS allows a single Telnet/SSH session,
// so a second one (audit, "Kiểm tra kết nối") would be refused or would
// push the poller out. The returned func gives d its own client back.
func (h *Hub) sharedCLI(routerID int64, d *draytekSource) func() {
	rs := h.get(routerID)
	if rs == nil || d == nil || d.cli == nil {
		return func() {}
	}
	rs.mu.RLock()
	src := rs.src
	rs.mu.RUnlock()
	run := asDraytek(src)
	if run == nil || run.cli == nil || run.cli == d.cli || run.cli.cfg != d.cli.cfg {
		return func() {}
	}
	own := d.cli
	d.cli = run.cli
	return func() { d.cli = own }
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

// bindOps runs one blocking transaction. It holds the router's CLI session
// for the whole transaction (see bindSession), so its commands are not queued
// behind the poller's reads and pings one by one.
type bindOps struct {
	cli *cliClient
	ctx context.Context
}

func (o *bindOps) run(cmd string) (string, error) {
	if !cliWriteCommandAllowed(cmd) {
		return "", fmt.Errorf("lệnh CLI không được phép: %q", cmd)
	}
	out, err := o.cli.runHeld(o.ctx, []string{cmd})
	if err != nil {
		return "", err
	}
	text := out[cmd]
	if strings.HasSuffix(cmd, " show") {
		return text, nil // a listing: admin comments may contain "error", "fail"…
	}
	// a refused change answers on its first lines
	lines := strings.SplitN(strings.TrimSpace(text), "\n", 3)
	if len(lines) > 2 {
		lines = lines[:2]
	}
	head := strings.ToLower(strings.Join(lines, "\n"))
	for _, bad := range []string{"unknown command", "command not found", "invalid", "error", "fail"} {
		if strings.Contains(head, bad) {
			return text, fmt.Errorf("router từ chối lệnh %q: %s", cmd, firstLine(text))
		}
	}
	return text, nil
}

// clearARP drops the router's ARP entry of a released IP. DrayOS keeps it
// pointing at the blocking MAC, so the next device on that IP (or the
// unblocked one) gets no traffic. A failure is not fatal: the entry ages out.
func (o *bindOps) clearARP(ip string) {
	o.run("ip arp del " + ip + " LAN")
}

// rawSnippet quotes router output for error messages (diagnosing formats).
func rawSnippet(t string) string {
	t = strings.Join(strings.Fields(t), " ")
	if t == "" {
		return "(rỗng)"
	}
	if len(t) > 300 {
		t = truncateUTF8(t, 300) + "…"
	}
	return "«" + t + "»"
}

// show reads the table. Firmware differs: the user guide prints an ON/OFF
// line first, but some builds print only the entries (nothing at all when
// the table is empty). Blank output therefore means "empty table, state
// unknown"; output that is neither blank nor understood is an error.
func (o *bindOps) show() (bindState, error) {
	t, err := o.run("ip bindmac show")
	if err != nil {
		return bindState{}, err
	}
	st := parseBindMAC(t)
	st.Raw = t
	switch {
	case st.Known, len(st.Entries) > 0:
	case strings.TrimSpace(t) == "" || reBindHeader.MatchString(t):
		st.Blank = true
	default:
		return st, fmt.Errorf("không hiểu kết quả lệnh “ip bindmac show” của router: %s", rawSnippet(t))
	}
	return st, nil
}

var reBindHeader = regexp.MustCompile(`(?i)^\s*(show all ip bind mac entries\.?\s*)?$`)

func (o *bindOps) setOn(on bool) error {
	cmd := map[bool]string{true: "ip bindmac on", false: "ip bindmac off"}[on]
	if _, err := o.run(cmd); err != nil {
		return err
	}
	st, err := o.show()
	if err != nil {
		return err
	}
	if st.Known && st.On != on { // builds without a state line cannot be checked here
		return fmt.Errorf("router không chuyển Bind IP to MAC sang %v (đọc lại: %s)", map[bool]string{true: "ON", false: "OFF"}[on], rawSnippet(st.Raw))
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

// unblockPrep is blockPrep without the "blocking enabled" check: entries
// left on the router must stay removable after blocking was switched off.
func (h *Hub) unblockPrep(routerID int64) (*RState, Router, error) {
	rs := h.get(routerID)
	if rs == nil {
		return nil, Router{}, ErrNotFound
	}
	rs.mu.RLock()
	cfg := rs.cfg
	rs.mu.RUnlock()
	return rs, cfg, nil
}

func (h *Hub) saveTurnedOn(rs *RState, v bool) error {
	return h.saveBlockCfg(rs, func(b *BlockCfg) { b.TurnedOn = v })
}

// saveBlockCfg changes the router's blocking state (not a setting the admin
// edits) in the database and in memory.
func (h *Hub) saveBlockCfg(rs *RState, change func(*BlockCfg)) error {
	rs.mu.RLock()
	id := rs.cfg.ID
	rs.mu.RUnlock()
	r, err := h.st.GetRouter(id)
	if err != nil {
		return err
	}
	change(&r.Opts.Block)
	if err := h.st.SaveRouter(r); err != nil {
		return err
	}
	rs.mu.Lock()
	change(&rs.cfg.Opts.Block)
	rs.mu.Unlock()
	return nil
}

// bindTx applies a set of IP additions/removals to the router's table as
// one unit: the function is switched on if needed (refusing when that would
// activate the admin's own entries), everything is read back, and on any
// mismatch the router is put back as it was.
func (h *Hub) bindTx(o *bindOps, rs *RState, add, del []string) error {
	if len(add) == 0 && len(del) == 0 {
		return nil
	}
	st, err := o.show()
	if err != nil {
		return err
	}
	for _, ip := range add {
		if e := st.find(ip); e != nil && !e.ours() {
			return fmt.Errorf("IP %s đã có trong bảng Bind IP to MAC của router (gắn với %s): DrayPulse không sửa mục do bạn tạo", ip, e.MAC)
		}
	}
	off := !st.Known || !st.On // unknown state: switch on explicitly
	if off && len(add) > 0 {
		var others []string
		for _, e := range st.Entries {
			if !e.ours() {
				others = append(others, e.IP)
			}
		}
		if len(others) > 0 {
			return fmt.Errorf("Bind IP to MAC đang TẮT nhưng bảng có %d mục do bạn tạo (%s). Bật chức năng sẽ áp dụng cả các mục này, nên DrayPulse không tự bật. Hãy kiểm tra/xoá các mục đó trong LAN → Bind IP to MAC rồi thử lại", len(others), strings.Join(others, ", "))
		}
	}
	var added, removed []string
	turnedOn := false
	undo := func() {
		// the transaction's own deadline may be what failed: undo on a fresh one
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		o.ctx = ctx
		for _, ip := range added {
			o.run("ip bindmac del " + ip)
			o.clearARP(ip)
		}
		for _, ip := range removed {
			o.run(fmt.Sprintf("ip bindmac add %s %s %s", ip, strings.ToLower(blockMAC), blockComment))
		}
		if turnedOn {
			o.setOn(false)
		}
	}
	for _, ip := range add {
		if st.find(ip) != nil {
			continue // already blocked by DrayPulse
		}
		added = append(added, ip) // before sending: an add whose answer is lost is undone too
		if _, err := o.run(fmt.Sprintf("ip bindmac add %s %s %s", ip, strings.ToLower(blockMAC), blockComment)); err != nil {
			undo()
			return err
		}
	}
	for _, ip := range del {
		e := st.find(ip)
		if e == nil {
			o.clearARP(ip) // the router dropped the entry but may keep its ARP line
			continue
		}
		if !e.ours() {
			undo()
			return fmt.Errorf("mục %s trong Bind IP to MAC không phải của DrayPulse (MAC %s)", ip, e.MAC)
		}
		if _, err := o.run("ip bindmac del " + ip); err != nil {
			undo()
			return err
		}
		removed = append(removed, ip)
		o.clearARP(ip)
	}
	if off && len(add) > 0 {
		if err := o.setOn(true); err != nil {
			undo()
			return err
		}
		turnedOn = true
	}
	after, err := o.show()
	if err != nil {
		undo()
		return err
	}
	for _, ip := range add {
		if e := after.find(ip); e == nil || !e.ours() || (after.Known && !after.On) {
			undo()
			return fmt.Errorf("router không lưu mục chặn cho %s – đã hoàn tác. Lệnh “ip bindmac show” sau khi thêm trả về: %s", ip, rawSnippet(after.Raw))
		}
	}
	for _, ip := range del {
		if after.find(ip) != nil {
			undo()
			return fmt.Errorf("router vẫn còn mục chặn %s sau khi xoá (đọc lại: %s)", ip, rawSnippet(after.Raw))
		}
	}
	if turnedOn {
		if err := h.saveTurnedOn(rs, true); err != nil {
			return err
		}
	}
	// nothing of DrayPulse's left: switch the function off if DrayPulse switched it on
	rs.mu.RLock()
	wasOurs := rs.cfg.Opts.Block.TurnedOn
	rs.mu.RUnlock()
	if wasOurs && len(after.Entries) == 0 && (after.On || !after.Known) {
		if err := o.setOn(false); err == nil {
			h.saveTurnedOn(rs, false)
		}
	}
	return nil
}

// observed maps what the router currently sees: IP → MAC and MAC → IPs,
// plus MACs per DHCP host name. Rows carrying DrayPulse's blocking MAC
// (a static ARP entry the router may create) are ignored.
//
// ARP and DHCP can disagree for a while (a stale ARP entry, an old lease):
// ipMACs keeps every MAC any source shows on an IP, so an IP is blocked for
// a device only when nobody else is seen on it, and released as soon as an
// unblocked device is.
type observed struct {
	ipMAC   map[string]string   // the most current MAC (ARP wins over DHCP)
	ipMACs  map[string][]string // every MAC seen on the IP (ARP, DHCP, syslog)
	macIPs  map[string][]string
	hostMAC map[string][]string
}

func observe(arp, lease []Row, hints ...dhcpHint) observed {
	ob := observed{ipMAC: map[string]string{}, ipMACs: map[string][]string{}, macIPs: map[string][]string{}, hostMAC: map[string][]string{}}
	seen := func(ip, mac string) bool {
		mac = normMAC(mac)
		if ip == "" || mac == "" || mac == blockMAC {
			return false
		}
		if !slicesContains(ob.ipMACs[ip], mac) {
			ob.ipMACs[ip] = append(ob.ipMACs[ip], mac)
		}
		return true
	}
	add := func(ip, mac, host string, prefer bool) {
		if !seen(ip, mac) {
			return
		}
		mac = normMAC(mac)
		if _, ok := ob.ipMAC[ip]; !ok || prefer {
			ob.ipMAC[ip] = mac
		}
		if !slicesContains(ob.macIPs[mac], ip) {
			ob.macIPs[mac] = append(ob.macIPs[mac], ip)
		}
		if h := strings.ToLower(strings.TrimSpace(host)); h != "" && !slicesContains(ob.hostMAC[h], mac) {
			ob.hostMAC[h] = append(ob.hostMAC[h], mac)
		}
	}
	for _, l := range lease {
		add(firstNonEmpty(l["active-address"], l["address"]), l["mac-address"], l["host-name"], false)
	}
	for _, a := range arp { // ARP is the live mapping: it wins over DHCP
		if truthy(a["invalid"]) {
			continue
		}
		add(a["address"], a["mac-address"], a["host"], true)
	}
	// syslog leases only tell who else uses an IP (they release, never block)
	for _, x := range hints {
		if seen(x.IP, x.MAC) {
			if _, ok := ob.ipMAC[x.IP]; !ok {
				ob.ipMAC[x.IP] = normMAC(x.MAC)
			}
		}
	}
	return ob
}

// unblockedOn returns a MAC seen on ip that is not blocked ("" if none).
func (ob observed) unblockedOn(ip string, blocked map[string]bool) string {
	if m := ob.ipMAC[ip]; m != "" && !blocked[m] {
		return m
	}
	for _, m := range ob.ipMACs[ip] {
		if !blocked[m] {
			return m
		}
	}
	return ""
}

func (h *Hub) currentObs(rs *RState) observed {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return observe(rs.Sections["arp"], rs.Sections["lease"])
}

// noteBlockErr records a failed router update: an event at most every
// 10 minutes for the same error, a notification at most once an hour
// (followBlocks retries every 15 s). Caller holds blockMu.
func (h *Hub) noteBlockErr(rs *RState, eff *effects, now int64, err error) {
	msg := "Không cập nhật được danh sách chặn trên router: " + err.Error()
	if msg == rs.blockErrMsg && now-rs.blockErrAt < 600_000 {
		return
	}
	notify := now-rs.blockErrNotified >= 3600_000
	rs.blockErrMsg, rs.blockErrAt = msg, now
	if notify {
		rs.blockErrNotified = now
	}
	eff.add(now, "warning", "⚠️", msg, notify)
}

package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"regexp"
	"sort"
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
	low := strings.ToLower(text)
	for _, bad := range []string{"unknown command", "command not found", "invalid", "error", "fail"} {
		if strings.Contains(low, bad) {
			return text, fmt.Errorf("router từ chối lệnh %q: %s", cmd, firstLine(text))
		}
	}
	return text, nil
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
		for _, ip := range added {
			o.run("ip bindmac del " + ip)
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
		if _, err := o.run(fmt.Sprintf("ip bindmac add %s %s %s", ip, strings.ToLower(blockMAC), blockComment)); err != nil {
			undo()
			return err
		}
		added = append(added, ip)
	}
	for _, ip := range del {
		e := st.find(ip)
		if e == nil {
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

func (h *Hub) refreshHasBlocks(rs *RState, routerID int64) {
	n := 0
	if d, err := h.st.ListDevices(routerID); err == nil {
		n += len(d)
	}
	rs.hasBlocks.Store(n > 0)
}

// BlockDevice blocks a device by MAC: every IP it uses now, and every IP it
// gets later, is blocked. ip may name an address seen with it right now.
func (h *Hub) BlockDevice(ctx context.Context, routerID int64, mac, ip, name, host, note string, matchHost bool, by string) (*Device, error) {
	return h.blockDevice(ctx, routerID, mac, ip, name, host, note, matchHost, by, "")
}

func (h *Hub) blockDevice(ctx context.Context, routerID int64, mac, ip, name, host, note string, matchHost bool, by, origin string) (*Device, error) {
	mac = normMAC(mac)
	if mac == "" || mac == zeroMAC || mac == blockMAC || mac == "FF:FF:FF:FF:FF:FF" {
		return nil, errors.New("địa chỉ MAC không hợp lệ")
	}
	sf := h.settings.blockSafety()
	if sf.macs[mac] {
		return nil, errProtected(mac)
	}
	rs, cfg, err := h.blockPrep(routerID)
	if err != nil {
		return nil, err
	}
	rs.blockMu.Lock()
	defer rs.blockMu.Unlock()
	devs, err := h.st.ListDevices(routerID)
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		if d.MAC == mac {
			return nil, errors.New("thiết bị này đã bị chặn")
		}
	}
	host = strings.TrimSpace(host)
	if matchHost && host == "" {
		return nil, errors.New("thiết bị không có tên máy (HOST ID) nên không thể bắt theo tên khi đổi MAC")
	}
	hostNote := ""
	if matchHost && sf.genericHost(host) {
		// "iPhone", "Redmi-12"… are shared by many devices: never follow them
		matchHost = false
		hostNote = fmt.Sprintf("; không theo dõi tên máy “%s” vì tên này phổ biến (Cài đặt → Chặn client an toàn)", host)
	}
	ob := h.currentObs(rs)
	ips := ob.macIPs[mac]
	if ip != "" && !slicesContains(ips, ip) {
		if other := ob.ipMAC[ip]; other != "" && other != mac {
			return nil, fmt.Errorf("IP %s hiện thuộc thiết bị khác (%s): không chặn IP này theo MAC %s", ip, other, mac)
		}
		ips = append(ips, ip)
	}
	var add []string
	for _, x := range ips {
		if err := h.checkBlockTarget(rs, x); err != nil {
			return nil, fmt.Errorf("%s: %v", x, err)
		}
		if err := sf.checkIP(x, ob); err != nil {
			return nil, err
		}
		if ob.unblockedOn(x, map[string]bool{mac: true}) != "" {
			continue // another device is also seen on this IP: do not cut it off
		}
		add = append(add, x)
	}
	if len(add) > 0 {
		o, done, err := h.bindSession(ctx, rs)
		if err != nil {
			return nil, err
		}
		err = h.bindTx(o, rs, add, nil)
		done()
		if err != nil {
			return nil, err
		}
	}
	now := nowMs()
	d := Device{MAC: mac, Name: name, Host: host, Note: note, ByUser: by, At: now, MatchHost: matchHost, Origin: origin, IPs: add}
	if d.IPs == nil {
		d.IPs = []string{}
	}
	if err := h.st.AddDevice(routerID, d); err != nil {
		return nil, err
	}
	for _, x := range add {
		h.st.AddBlock(routerID, Block{IP: x, MAC: mac, Name: name, ByUser: by, At: now})
	}
	h.st.DeleteSuggestion(routerID, mac)
	rs.hasBlocks.Store(true)
	var eff effects
	what := "chưa thấy IP, sẽ chặn ngay khi thiết bị xuất hiện"
	if len(add) > 0 {
		what = "IP " + strings.Join(add, ", ")
	}
	eff.add(now, "warning", "⛔", fmt.Sprintf("Đã chặn thiết bị %s (%s, %s) – bởi %s%s", firstNonEmpty(name, host, mac), mac, what, by, hostNote), false)
	h.apply(cfg, eff)
	return &d, nil
}

// bindSession takes the router's CLI session for one transaction; the
// returned func releases it. Nothing else may use the CLI client before then.
func (h *Hub) bindSession(ctx context.Context, rs *RState) (*bindOps, func(), error) {
	cli, done, err := h.blockCLI(rs)
	if err != nil {
		return nil, nil, err
	}
	cli.mu.Lock()
	return &bindOps{cli: cli, ctx: ctx}, func() { cli.mu.Unlock(); done() }, nil
}

// BlockClient blocks a single IP without tying it to a device.
func (h *Hub) BlockClient(ctx context.Context, routerID int64, ip, mac, name, note, by string) (*Block, error) {
	ip = strings.TrimSpace(ip)
	rs, cfg, err := h.blockPrep(routerID)
	if err != nil {
		return nil, err
	}
	if err := h.checkBlockTarget(rs, ip); err != nil {
		return nil, err
	}
	sf := h.settings.blockSafety()
	if m := normMAC(mac); m != "" && sf.macs[m] {
		return nil, errProtected(m)
	}
	if err := sf.checkIP(ip, h.currentObs(rs)); err != nil {
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
	o, done, err := h.bindSession(ctx, rs)
	if err != nil {
		return nil, err
	}
	defer done()
	if err := h.bindTx(o, rs, []string{ip}, nil); err != nil {
		return nil, err
	}
	b := Block{IP: ip, Name: name, Note: note, ByUser: by, At: nowMs()}
	if err := h.st.AddBlock(routerID, b); err != nil {
		return nil, err
	}
	var eff effects
	eff.add(nowMs(), "warning", "⛔", fmt.Sprintf("Đã chặn IP %s khỏi mạng – bởi %s", blockLabel(b), by), false)
	h.apply(cfg, eff)
	return &b, nil
}

func blockLabel(b Block) string {
	if b.Name != "" {
		return b.Name + " (" + b.IP + ")"
	}
	return b.IP
}

// UnblockClient removes a manual IP-only block.
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
	if target.MAC != "" {
		return fmt.Errorf("IP %s đang bị chặn theo thiết bị %s: hãy bỏ chặn thiết bị đó", ip, target.MAC)
	}
	o, done, err := h.bindSession(ctx, rs)
	if err != nil {
		return err
	}
	defer done()
	if err := h.bindTx(o, rs, nil, []string{ip}); err != nil {
		return err
	}
	if err := h.st.DeleteBlock(routerID, ip); err != nil {
		return err
	}
	var eff effects
	eff.add(nowMs(), "info", "✅", fmt.Sprintf("Đã bỏ chặn IP %s – bởi %s", blockLabel(*target), by), false)
	h.apply(cfg, eff)
	return nil
}

// UnblockDevice removes a device block and every IP blocked for it.
func (h *Hub) UnblockDevice(ctx context.Context, routerID int64, mac, by string) error {
	mac = normMAC(mac)
	rs, cfg, err := h.blockPrep(routerID)
	if err != nil {
		return err
	}
	rs.blockMu.Lock()
	defer rs.blockMu.Unlock()
	devs, err := h.st.ListDevices(routerID)
	if err != nil {
		return err
	}
	var target *Device
	for i := range devs {
		if devs[i].MAC == mac {
			target = &devs[i]
		}
	}
	if target == nil {
		return errors.New("thiết bị này không bị chặn")
	}
	if len(target.IPs) > 0 {
		o, done, err := h.bindSession(ctx, rs)
		if err != nil {
			return err
		}
		err = h.bindTx(o, rs, nil, target.IPs)
		done()
		if err != nil {
			return err
		}
	}
	if err := h.st.DeleteDevice(routerID, mac); err != nil {
		return err
	}
	h.st.DeleteSuggestionsFor(routerID, mac)
	h.refreshHasBlocks(rs, routerID)
	var eff effects
	eff.add(nowMs(), "info", "✅", fmt.Sprintf("Đã bỏ chặn thiết bị %s (%s) – bởi %s", firstNonEmpty(target.Name, target.Host, mac), mac, by), false)
	h.apply(cfg, eff)
	return nil
}

// followBlocks keeps device blocks up to date with what the router sees:
//   - a blocked MAC that got another IP (new DHCP lease) → block that IP,
//     unless another, unblocked device is also seen on it,
//   - an IP blocked for a device but now seen with another, unblocked MAC
//     (ARP, DHCP or a syslog lease) → release it at once,
//   - protected MACs/IPs (Settings) → never blocked, released if blocked,
//   - with MatchHost, a new MAC carrying the device's (uncommon) DHCP host
//     name → only a suggestion and an alert; an admin confirms the block.
//
// Automatic blocks are capped per router and hour: above the limit
// auto-blocking pauses until an admin resumes it.
//
// It runs after every client read, every 15 s while devices are blocked and
// right after syslog reports a DHCP lease.
func (h *Hub) followBlocks(ctx context.Context, rs *RState, arp, lease []Row) {
	if !rs.hasBlocks.Load() || !rs.blockMu.TryLock() {
		return
	}
	defer rs.blockMu.Unlock()
	rs.mu.RLock()
	cfg := rs.cfg
	rs.mu.RUnlock()
	if !cfg.Opts.Block.Enabled {
		return
	}
	devs, err := h.st.ListDevices(cfg.ID)
	if err != nil {
		return
	}
	blocks, _ := h.st.ListBlocks(cfg.ID)
	if len(devs) == 0 && len(blocks) == 0 {
		return
	}
	owner := map[string]string{} // blocked IP → device MAC ("" = manual)
	for _, b := range blocks {
		owner[b.IP] = b.MAC
	}
	now := nowMs()
	sf := h.settings.blockSafety()
	ob := observe(arp, lease, rs.recentHints(now)...)
	blocked := map[string]bool{}
	for _, d := range devs {
		blocked[d.MAC] = !sf.macs[d.MAC] // a protected device counts as not blocked
	}
	var eff effects
	// 1. same host name, new MAC: suggest, never block on our own
	h.suggestByHost(cfg.ID, devs, ob, blocked, sf, now, &eff)
	// 2. IPs to add / release
	var add, del []string
	addFor, delWhy := map[string]string{}, map[string]string{}
	for _, d := range devs {
		if !blocked[d.MAC] {
			continue
		}
		for _, ip := range ob.macIPs[d.MAC] {
			if o, ok := owner[ip]; ok && (o == d.MAC || o == "") {
				if o == "" && sf.checkIP(ip, ob) == nil { // a manual IP block now belongs to the device
					h.st.AddBlock(cfg.ID, Block{IP: ip, MAC: d.MAC, Name: d.Name, ByUser: "DrayPulse", At: now})
					owner[ip] = d.MAC
				}
				continue
			}
			if _, dup := addFor[ip]; dup || ob.unblockedOn(ip, blocked) != "" || sf.checkIP(ip, ob) != nil || h.checkBlockTarget(rs, ip) != nil {
				continue
			}
			add, addFor[ip] = append(add, ip), d.MAC
		}
	}
	for ip, o := range owner {
		why := ""
		switch {
		case sf.checkIP(ip, ob) != nil || (o != "" && sf.macs[o]):
			why = "nằm trong danh sách “Không bao giờ chặn”"
		case o == "": // a manual IP block stays until an admin removes it
		default:
			if m := ob.unblockedOn(ip, blocked); m != "" {
				why = "thiết bị khác (" + m + ") đang dùng IP này"
			}
		}
		if why != "" {
			del, delWhy[ip] = append(del, ip), why
		}
	}
	sort.Strings(add)
	sort.Strings(del)
	// 3. safety limit for automatic blocks
	if len(add) > 0 {
		recent := rs.autoRecent(now)
		switch {
		case cfg.Opts.Block.AutoPaused:
			add = nil
		case recent+len(add) > sf.autoMax:
			if err := h.saveBlockCfg(rs, func(b *BlockCfg) { b.AutoPaused, b.AutoPausedAt = true, now }); err != nil {
				log.Printf("tạm dừng tự động chặn: %v", err)
			}
			eff.add(now, "warning", "🛑", fmt.Sprintf("Đã TẠM DỪNG tự động chặn: DrayPulse định chặn thêm %d IP (%s), vượt giới hạn %d lượt/giờ (đã có %d lượt trong 1 giờ qua). Không IP nào bị chặn thêm. Kiểm tra tab Client rồi bấm “Tiếp tục tự động chặn”",
				len(add), strings.Join(add, ", "), sf.autoMax, recent), true)
			add = nil
		}
	}
	if len(add) == 0 && len(del) == 0 {
		if len(eff.alerts) > 0 {
			h.apply(cfg, eff)
		}
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	o, done, err := h.bindSession(cctx, rs)
	if err != nil {
		log.Printf("theo dõi thiết bị bị chặn: %v", err)
		h.apply(cfg, eff)
		return
	}
	defer done()
	if err := h.bindTx(o, rs, add, del); err != nil {
		eff.add(now, "warning", "⚠️", "Không cập nhật được danh sách chặn trên router: "+err.Error(), true)
		h.apply(cfg, eff)
		return
	}
	rs.autoRecord(now, len(add))
	names := map[string]string{}
	for _, d := range devs {
		names[d.MAC] = firstNonEmpty(d.Name, d.Host, d.MAC)
	}
	for _, ip := range add {
		mac := addFor[ip]
		h.st.AddBlock(cfg.ID, Block{IP: ip, MAC: mac, Name: names[mac], ByUser: "DrayPulse", At: now})
		eff.add(now, "warning", "⛔", fmt.Sprintf("Thiết bị bị chặn %s nhận IP mới %s – đã chặn IP này", names[mac], ip), false)
	}
	for _, ip := range del {
		h.st.DeleteBlock(cfg.ID, ip)
		eff.add(now, "info", "↩️", fmt.Sprintf("Nhả chặn IP %s: %s", ip, delWhy[ip]), false)
	}
	h.refreshHasBlocks(rs, cfg.ID)
	h.apply(cfg, eff)
}

// BlockInfo is the blocking summary shown with a router.
type BlockInfo struct {
	Devices      []Device     `json:"devices"`
	IPs          []Block      `json:"ips"`         // every blocked IP (device-owned and manual)
	Suggestions  []Suggestion `json:"suggestions"` // same host name, new MAC: waiting for an admin
	AutoPaused   bool         `json:"autoPaused"`  // safety limit hit: automatic blocking stopped
	AutoPausedAt int64        `json:"autoPausedAt"`
}

// BlockStatus compares DrayPulse's list with the router (read-only).
type BlockStatus struct {
	Devices []Device `json:"devices"`
	Blocks  []Block  `json:"blocks"`
	On      *bool    `json:"on"`
	Strict  bool     `json:"strict"`
	Missing []string `json:"missing"` // blocked here, not on the router
	Extra   []string `json:"extra"`   // DrayPulse entries on the router not known here
	Others  int      `json:"others"`  // entries created by someone else
	Raw     string   `json:"raw"`     // the router's own output, for diagnosis
}

func (h *Hub) BlockState(ctx context.Context, routerID int64, live bool) (*BlockStatus, error) {
	blocks, err := h.st.ListBlocks(routerID)
	if err != nil {
		return nil, err
	}
	devs, err := h.st.ListDevices(routerID)
	if err != nil {
		return nil, err
	}
	out := &BlockStatus{Devices: devs, Blocks: blocks, Missing: []string{}, Extra: []string{}}
	if !live {
		return out, nil
	}
	rs, _, err := h.blockPrep(routerID)
	if err != nil {
		return out, nil
	}
	rs.blockMu.Lock()
	defer rs.blockMu.Unlock()
	o, done, err := h.bindSession(ctx, rs)
	if err != nil {
		return nil, err
	}
	defer done()
	st, err := o.show()
	if err != nil {
		return nil, err
	}
	if st.Known {
		on := st.On
		out.On = &on
	}
	out.Strict = st.Strict
	known := map[string]bool{}
	for _, b := range blocks {
		known[b.IP] = true
		if e := st.find(b.IP); e == nil || !e.ours() {
			out.Missing = append(out.Missing, b.IP)
		}
	}
	out.Raw = st.Raw
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

// followTick re-reads ARP and DHCP every 15 s while devices are blocked, so a
// blocked device that gets a new IP is cut off again within seconds. force
// (a DHCP lease reported by syslog) shortens the wait to 3 s.
func (h *Hub) followTick(ctx context.Context, rs *RState, src Source, force bool) {
	gap := 15 * time.Second
	if force {
		gap = 3 * time.Second
	}
	if !rs.hasBlocks.Load() || time.Since(rs.lastFollow) < gap {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("router %d: lỗi khi theo dõi thiết bị bị chặn: %v", rs.id, r)
		}
	}()
	rs.lastFollow = time.Now()
	d := asDraytek(src)
	if d == nil || d.cli == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := d.cli.Run(cctx, "ip arp status", "srv dhcp status")
	if err != nil {
		return
	}
	h.followBlocks(ctx, rs, parseARP(out["ip arp status"]), parseDHCP(out["srv dhcp status"]))
}

package app

import (
	"context"
	"errors"
	"fmt"
	"log"
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
type observed struct {
	ipMAC   map[string]string
	macIPs  map[string][]string
	hostMAC map[string][]string
}

func observe(arp, lease []Row) observed {
	ob := observed{ipMAC: map[string]string{}, macIPs: map[string][]string{}, hostMAC: map[string][]string{}}
	add := func(ip, mac, host string, prefer bool) {
		mac = normMAC(mac)
		if ip == "" || mac == "" || mac == blockMAC {
			return
		}
		if _, ok := ob.ipMAC[ip]; ok && !prefer {
			return
		}
		ob.ipMAC[ip] = mac
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
	return ob
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
	mac = normMAC(mac)
	if mac == "" || mac == zeroMAC || mac == blockMAC || mac == "FF:FF:FF:FF:FF:FF" {
		return nil, errors.New("địa chỉ MAC không hợp lệ")
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
	ips := h.currentObs(rs).macIPs[mac]
	if ip != "" && !slicesContains(ips, ip) {
		ips = append(ips, ip)
	}
	var add []string
	for _, x := range ips {
		if err := h.checkBlockTarget(rs, x); err != nil {
			return nil, fmt.Errorf("%s: %v", x, err)
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
	d := Device{MAC: mac, Name: name, Host: host, Note: note, ByUser: by, At: now, MatchHost: matchHost, IPs: add}
	if err := h.st.AddDevice(routerID, d); err != nil {
		return nil, err
	}
	for _, x := range add {
		h.st.AddBlock(routerID, Block{IP: x, MAC: mac, Name: name, ByUser: by, At: now})
	}
	rs.hasBlocks.Store(true)
	var eff effects
	what := "chưa thấy IP, sẽ chặn ngay khi thiết bị xuất hiện"
	if len(add) > 0 {
		what = "IP " + strings.Join(add, ", ")
	}
	eff.add(now, "warning", "⛔", fmt.Sprintf("Đã chặn thiết bị %s (%s, %s) – bởi %s", firstNonEmpty(name, host, mac), mac, what, by), false)
	h.apply(cfg, eff)
	return &d, nil
}

func (h *Hub) bindSession(ctx context.Context, rs *RState) (*bindOps, func(), error) {
	cli, done, err := h.blockCLI(rs)
	if err != nil {
		return nil, nil, err
	}
	return &bindOps{cli: cli, ctx: ctx}, done, nil
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
	h.refreshHasBlocks(rs, routerID)
	var eff effects
	eff.add(nowMs(), "info", "✅", fmt.Sprintf("Đã bỏ chặn thiết bị %s (%s) – bởi %s", firstNonEmpty(target.Name, target.Host, mac), mac, by), false)
	h.apply(cfg, eff)
	return nil
}

// followBlocks keeps device blocks up to date with what the router sees:
//   - a blocked MAC that got another IP (new DHCP lease) → block that IP,
//   - an IP blocked for a device but now used by another, unblocked MAC → release it,
//   - with MatchHost, a new MAC carrying the device's DHCP host name → block it too.
//
// It runs after every client read and every 15 s while devices are blocked.
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
	if err != nil || len(devs) == 0 {
		return
	}
	blocks, _ := h.st.ListBlocks(cfg.ID)
	owner := map[string]string{} // blocked IP → device MAC ("" = manual)
	for _, b := range blocks {
		owner[b.IP] = b.MAC
	}
	ob := observe(arp, lease)
	blocked := map[string]bool{}
	for _, d := range devs {
		blocked[d.MAC] = true
	}
	now := nowMs()
	var eff effects
	var newDevs []Device
	// 1. same host name, new MAC
	for _, d := range devs {
		if !d.MatchHost || d.Host == "" {
			continue
		}
		for _, m := range ob.hostMAC[strings.ToLower(d.Host)] {
			if blocked[m] {
				continue
			}
			blocked[m] = true
			nd := Device{MAC: m, Name: d.Name, Host: d.Host, Note: d.Note, ByUser: "DrayPulse", At: now, MatchHost: true,
				Origin: "cùng tên máy với " + d.MAC}
			newDevs = append(newDevs, nd)
			eff.add(now, "warning", "⛔", fmt.Sprintf("Thiết bị bị chặn %s xuất hiện với MAC mới %s (cùng tên máy) – đã tự chặn", firstNonEmpty(d.Name, d.Host), m), true)
		}
	}
	for _, nd := range newDevs {
		if err := h.st.AddDevice(cfg.ID, nd); err != nil {
			log.Printf("chặn thiết bị %s: %v", nd.MAC, err)
		}
		devs = append(devs, nd)
	}
	// 2. IPs to add / release
	var add, del []string
	addFor := map[string]string{}
	for _, d := range devs {
		for _, ip := range ob.macIPs[d.MAC] {
			if o, ok := owner[ip]; ok && (o == d.MAC || o == "") {
				if o == "" { // a manual IP block now belongs to the device
					h.st.AddBlock(cfg.ID, Block{IP: ip, MAC: d.MAC, Name: d.Name, ByUser: "DrayPulse", At: now})
				}
				continue
			}
			if h.checkBlockTarget(rs, ip) != nil {
				continue
			}
			add, addFor[ip] = append(add, ip), d.MAC
		}
	}
	for ip, o := range owner {
		if o == "" {
			continue
		}
		if m, seen := ob.ipMAC[ip]; seen && m != o && !blocked[m] {
			del = append(del, ip)
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
		return
	}
	defer done()
	if err := h.bindTx(o, rs, add, del); err != nil {
		eff.add(now, "warning", "⚠️", "Không cập nhật được danh sách chặn trên router: "+err.Error(), true)
		h.apply(cfg, eff)
		return
	}
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
		eff.add(now, "info", "↩️", fmt.Sprintf("Nhả chặn IP %s: thiết bị khác (%s) đang dùng IP này", ip, ob.ipMAC[ip]), false)
	}
	h.apply(cfg, eff)
}

// BlockInfo is the blocking summary shown with a router.
type BlockInfo struct {
	Devices []Device `json:"devices"`
	IPs     []Block  `json:"ips"` // every blocked IP (device-owned and manual)
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
// blocked device that gets a new IP is cut off again within seconds.
func (h *Hub) followTick(ctx context.Context, rs *RState, src Source) {
	if !rs.hasBlocks.Load() || time.Since(rs.lastFollow) < 15*time.Second {
		return
	}
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

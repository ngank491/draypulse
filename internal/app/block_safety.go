package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// ---------- Safety rails for client blocking ----------
//
// Blocking by host name once cascaded to hundreds of phones that all called
// themselves "iPhone" or "Redmi-12". Since then:
//   - a host-name match is only a suggestion an admin confirms, and common
//     factory names are never matched (Settings → blockHostIgnore),
//   - automatic blocks are capped per router and hour (blockAutoMax); above
//     the cap auto-blocking pauses until an admin resumes it,
//   - protected MACs/IPs (blockProtected) are never blocked,
//   - an admin can remove every DrayPulse block of a router at once.

func errProtected(what string) error {
	return fmt.Errorf("%s nằm trong danh sách “Không bao giờ chặn” (Cài đặt → Chặn client an toàn)", what)
}

// checkIP refuses a protected IP, or an IP on which a protected MAC is seen.
func (b blockSafety) checkIP(ip string, ob observed) error {
	if b.ips[ip] {
		return errProtected("IP " + ip)
	}
	for _, m := range ob.ipMACs[ip] {
		if b.macs[m] {
			return errProtected(fmt.Sprintf("IP %s đang được thiết bị %s dùng, thiết bị này", ip, m))
		}
	}
	return nil
}

// suggestByHost records a suggestion (and alerts once) when exactly one new,
// unblocked MAC carries the uncommon host name of a device blocked with
// MatchHost. Nothing is blocked here.
func (h *Hub) suggestByHost(routerID int64, devs []Device, ob observed, blocked map[string]bool, sf blockSafety, now int64, eff *effects) {
	var known map[string]bool
	for _, d := range devs {
		if !d.MatchHost || !blocked[d.MAC] || sf.genericHost(d.Host) {
			continue
		}
		var cand []string
		for _, m := range ob.hostMAC[strings.ToLower(strings.TrimSpace(d.Host))] {
			if !blocked[m] && !sf.macs[m] {
				cand = append(cand, m)
			}
		}
		if len(cand) != 1 {
			continue // nobody, or a name several devices share: not a reliable match
		}
		m := cand[0]
		ips := ob.macIPs[m]
		protected := false
		for _, ip := range ips {
			protected = protected || sf.checkIP(ip, ob) != nil
		}
		if protected {
			continue
		}
		if known == nil {
			known = map[string]bool{}
			l, err := h.st.ListSuggestions(routerID, true)
			if err != nil {
				return
			}
			for _, x := range l {
				known[x.MAC] = true
			}
		}
		if known[m] {
			continue // already suggested (or dismissed by an admin)
		}
		known[m] = true
		x := Suggestion{MAC: m, Host: d.Host, RefMAC: d.MAC, Name: d.Name, At: now}
		if len(ips) > 0 {
			x.IP = ips[0]
		}
		if err := h.st.AddSuggestion(routerID, x); err != nil {
			continue
		}
		where := ""
		if x.IP != "" {
			where = ", IP " + x.IP
		}
		eff.add(now, "warning", "❓", fmt.Sprintf("Có thể thiết bị bị chặn %s đã đổi MAC: MAC mới %s%s mang cùng tên máy “%s”. DrayPulse KHÔNG tự chặn – vào tab Client để xác nhận “Chặn” hoặc “Bỏ qua”",
			firstNonEmpty(d.Name, d.Host, d.MAC), m, where, d.Host), true)
	}
}

// autoCount counts the IPs blocked automatically for a device in the last
// hour (caller holds blockMu).
func (rs *RState) autoCount(mac string, now int64) int {
	if rs.autoAdds == nil {
		rs.autoAdds, rs.limitNoted = map[string][]int64{}, map[string]int64{}
	}
	var keep []int64
	for _, t := range rs.autoAdds[mac] {
		if now-t < 3600_000 {
			keep = append(keep, t)
		}
	}
	if keep == nil {
		delete(rs.autoAdds, mac)
	} else {
		rs.autoAdds[mac] = keep
	}
	return len(keep)
}

func (rs *RState) autoRecord(mac string, now int64) {
	if rs.autoAdds == nil {
		rs.autoAdds, rs.limitNoted = map[string][]int64{}, map[string]int64{}
	}
	rs.autoAdds[mac] = append(rs.autoAdds[mac], now)
}

func (rs *RState) resetAuto() {
	rs.autoAdds, rs.limitNoted = map[string][]int64{}, map[string]int64{}
}

// AcceptSuggestion blocks the suggested MAC (an admin confirmed it).
func (h *Hub) AcceptSuggestion(ctx context.Context, routerID int64, mac, by string) (*Device, error) {
	mac = normMAC(mac)
	l, err := h.st.ListSuggestions(routerID, false)
	if err != nil {
		return nil, err
	}
	for _, x := range l {
		if x.MAC == mac {
			if devs, _ := h.st.ListDevices(routerID); slicesContains(deviceMACs(devs), mac) {
				h.st.DeleteSuggestion(routerID, mac) // blocked meanwhile
				return nil, errors.New("thiết bị này đã bị chặn")
			}
			// the IP of the suggestion may have moved on: block what the router sees now
			return h.blockDevice(ctx, routerID, x.MAC, "", x.Name, x.Host, "", true, by,
				fmt.Sprintf("cùng tên máy với %s, xác nhận bởi %s", x.RefMAC, by))
		}
	}
	return nil, errors.New("không còn gợi ý chặn này")
}

// DismissSuggestion keeps the MAC from being suggested again.
func (h *Hub) DismissSuggestion(routerID int64, mac, by string) error {
	mac = normMAC(mac)
	if err := h.st.DismissSuggestion(routerID, mac); err != nil {
		return errors.New("không còn gợi ý chặn này")
	}
	if rs := h.get(routerID); rs != nil {
		rs.mu.RLock()
		cfg := rs.cfg
		rs.mu.RUnlock()
		var eff effects
		eff.add(nowMs(), "info", "👌", fmt.Sprintf("Bỏ qua gợi ý chặn MAC %s – bởi %s", mac, by), false)
		h.apply(cfg, eff)
	}
	return nil
}

// ResumeAuto lets automatic blocking run again after the safety limit.
func (h *Hub) ResumeAuto(routerID int64, by string) error {
	rs := h.get(routerID)
	if rs == nil {
		return ErrNotFound
	}
	rs.blockMu.Lock()
	defer rs.blockMu.Unlock()
	if err := h.saveBlockCfg(rs, func(b *BlockCfg) { b.AutoPaused, b.AutoPausedAt = false, 0 }); err != nil {
		return err
	}
	rs.resetAuto()
	rs.mu.RLock()
	cfg := rs.cfg
	rs.mu.RUnlock()
	var eff effects
	eff.add(nowMs(), "info", "▶️", "Tiếp tục tự động chặn – bởi "+by, false)
	h.apply(cfg, eff)
	return nil
}

// UnblockAll removes every DrayPulse entry from the router's Bind IP to MAC
// table and forgets every blocked device/IP of the router. Entries created
// by the admin stay; the function is switched off only when DrayPulse
// switched it on and the table is empty afterwards. It works even when
// blocking was disabled for the router, so leftovers can be cleaned up.
func (h *Hub) UnblockAll(ctx context.Context, routerID int64, by string) (int, error) {
	rs := h.get(routerID)
	if rs == nil {
		return 0, ErrNotFound
	}
	rs.blockMu.Lock()
	defer rs.blockMu.Unlock()
	blocks, err := h.st.ListBlocks(routerID)
	if err != nil {
		return 0, err
	}
	devs, err := h.st.ListDevices(routerID)
	if err != nil {
		return 0, err
	}
	o, done, err := h.bindSession(ctx, rs)
	if err != nil {
		return 0, err
	}
	defer done()
	st, err := o.show()
	if err != nil {
		return 0, err
	}
	var del []string
	for _, e := range st.Entries {
		if e.ours() && !slicesContains(del, e.IP) {
			del = append(del, e.IP)
		}
	}
	for _, b := range blocks { // entries the router dropped on its own can leave ARP lines behind
		if !slicesContains(del, b.IP) {
			o.clearARP(b.IP)
		}
	}
	if len(del) > 0 {
		if err := h.bindTx(o, rs, nil, del); err != nil {
			return 0, err
		}
	} else {
		// nothing left on the router: still switch off what DrayPulse switched on
		rs.mu.RLock()
		wasOurs := rs.cfg.Opts.Block.TurnedOn
		rs.mu.RUnlock()
		if wasOurs && len(st.Entries) == 0 && (st.On || !st.Known) {
			if err := o.setOn(false); err == nil {
				h.saveTurnedOn(rs, false)
			}
		}
	}
	if err := h.st.DeleteAllBlocks(routerID); err != nil {
		return len(del), err
	}
	rs.hasBlocks.Store(false)
	rs.resetAuto()
	rs.mu.Lock()
	rs.drift = nil
	rs.mu.Unlock()
	rs.mu.RLock()
	cfg := rs.cfg
	rs.mu.RUnlock()
	var eff effects
	eff.add(nowMs(), "warning", "✅", fmt.Sprintf("Đã bỏ chặn TẤT CẢ: %d thiết bị, %d IP (%d mục DrayPulse trên router) – bởi %s", len(devs), len(blocks), len(del), by), true)
	h.apply(cfg, eff)
	return len(del), nil
}

func deviceMACs(devs []Device) []string {
	out := make([]string, len(devs))
	for i, d := range devs {
		out[i] = d.MAC
	}
	return out
}

// ---------- comparison with the router ----------

// BlockDrift is the last comparison of DrayPulse's blocks with the router.
type BlockDrift struct {
	At       int64    `json:"at"`
	Missing  []string `json:"missing"`  // blocked here, gone from the router
	Readded  []string `json:"readded"`  // … and added again
	Released []string `json:"released"` // … and released: the device no longer uses the IP
	Extra    []string `json:"extra"`    // DrayPulse entries on the router unknown here (removed)
	Stale    []string `json:"stale"`    // ARP lines left pointing at the blocking MAC (cleared)
	Error    string   `json:"error,omitempty"`
}

// reconcileEvery is how often the router's table is compared with the DB.
var reconcileEvery = 5 * time.Minute

// reconcileBlocks compares the router's Bind IP to MAC table and ARP with
// DrayPulse's blocks (Vigor 3912S was seen dropping entries on its own):
//   - a missing entry is added again while its device (or a manual IP block)
//     still uses the IP; otherwise the block is released,
//   - DrayPulse entries the DB does not know are removed,
//   - ARP lines left pointing at the blocking MAC are cleared.
//
// arp is the router's fresh ARP table (all rows, blocking MAC included).
func (h *Hub) reconcileBlocks(ctx context.Context, rs *RState, arp, lease []Row) {
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
	blocks, err := h.st.ListBlocks(cfg.ID)
	if err != nil {
		return
	}
	now := nowMs()
	ob := observe(arp, lease)
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	o, done, err := h.bindSession(cctx, rs)
	if err != nil {
		return
	}
	defer done()
	st, err := o.show()
	if err != nil {
		return
	}
	dr := &BlockDrift{At: now, Missing: []string{}, Readded: []string{}, Released: []string{}, Extra: []string{}, Stale: []string{}}
	known := map[string]bool{}
	var readd []string
	for _, b := range blocks {
		known[b.IP] = true
		if e := st.find(b.IP); e != nil && e.ours() {
			continue
		}
		dr.Missing = append(dr.Missing, b.IP)
		if b.MAC == "" || slicesContains(ob.ipMACs[b.IP], b.MAC) {
			readd = append(readd, b.IP) // still in use by the blocked device (or a manual block)
			continue
		}
		h.st.DeleteBlock(cfg.ID, b.IP) // the device moved on: follow it, not the old IP
		o.clearARP(b.IP)
		dr.Released = append(dr.Released, b.IP)
	}
	var extra []string
	for _, e := range st.Entries {
		if e.ours() && !known[e.IP] {
			extra = append(extra, e.IP)
		}
	}
	for _, a := range arp {
		ip := a["address"]
		if normMAC(a["mac-address"]) == blockMAC && ip != "" && !known[ip] && !slicesContains(extra, ip) {
			o.clearARP(ip)
			dr.Stale = append(dr.Stale, ip)
		}
	}
	if len(extra) > 0 {
		if err := h.bindTx(o, rs, nil, extra); err != nil {
			dr.Error = err.Error()
		} else {
			dr.Extra = extra
		}
	}
	if len(readd) > 0 {
		if err := h.bindTx(o, rs, readd, nil); err != nil {
			dr.Error = err.Error()
		} else {
			dr.Readded = readd
		}
	}
	rs.mu.Lock()
	rs.drift = dr
	rs.mu.Unlock()
	if len(dr.Missing)+len(dr.Extra)+len(dr.Stale) == 0 {
		return
	}
	var eff effects
	msg := fmt.Sprintf("Đối chiếu với router: %d mục chặn đã mất khỏi router (không do DrayPulse xoá)", len(dr.Missing))
	if len(dr.Readded) > 0 {
		msg += fmt.Sprintf("; đã thêm lại %d (%s)", len(dr.Readded), strings.Join(dr.Readded, ", "))
	}
	if len(dr.Released) > 0 {
		msg += fmt.Sprintf("; nhả %d IP thiết bị không còn dùng (%s)", len(dr.Released), strings.Join(dr.Released, ", "))
	}
	if len(dr.Extra) > 0 {
		msg += fmt.Sprintf("; xoá %d mục DrayPulse lạ (%s)", len(dr.Extra), strings.Join(dr.Extra, ", "))
	}
	if len(dr.Stale) > 0 {
		msg += fmt.Sprintf("; xoá %d dòng ARP còn trỏ về MAC chặn (%s)", len(dr.Stale), strings.Join(dr.Stale, ", "))
	}
	if dr.Error != "" {
		msg += "; lỗi: " + dr.Error
	}
	eff.add(now, "warning", "🔁", msg, len(dr.Missing) > 0 && now-rs.blockErrNotified >= 3600_000)
	if len(dr.Missing) > 0 && now-rs.blockErrNotified >= 3600_000 {
		rs.blockErrNotified = now
	}
	h.refreshHasBlocks(rs, cfg.ID)
	h.apply(cfg, eff)
}

// ---------- DHCP leases reported by syslog ----------

// dhcpHint is a lease seen in a syslog line: it tells that a MAC uses an IP.
type dhcpHint struct {
	IP, MAC string
	At      int64
}

const hintKeep = 120_000 // syslog leases count for 2 minutes

var (
	reSyslogDHCP   = regexp.MustCompile(`(?i)\bdhcp`)
	reSyslogDHCPKw = regexp.MustCompile(`(?i)\b(ack|assign\w*|offer\w*|lease\w*|request\w*|releas\w*|bound|allocat\w*|discover\w*|renew\w*|inform)\b`)
	reSyslogIPv4   = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	reSyslogMAC    = regexp.MustCompile(`(?i)\b([0-9a-f]{2}(?:[-:][0-9a-f]{2}){5})\b`)
)

// parseDHCPSyslog recognises a DHCP lease line. ok: the line is about DHCP
// leases (worth an immediate follow); ip/mac are filled only when the line
// names exactly one private client IP and one MAC, so an ambiguous line
// (server and client address) is never misread.
func parseDHCPSyslog(text string) (ip, mac string, ok bool) {
	if !reSyslogDHCP.MatchString(text) || !reSyslogDHCPKw.MatchString(text) {
		return "", "", false
	}
	var ips []string
	for _, m := range reSyslogIPv4.FindAllStringSubmatch(text, -1) {
		if a, err := netip.ParseAddr(m[1]); err == nil && a.Is4() && a.IsPrivate() && !slicesContains(ips, m[1]) {
			ips = append(ips, m[1])
		}
	}
	macs := reSyslogMAC.FindAllStringSubmatch(text, -1)
	if len(ips) == 1 && len(macs) == 1 {
		if m := normMAC(macs[0][1]); m != "" {
			return ips[0], m, true
		}
	}
	return "", "", true
}

// noteSyslogDHCP is called with rs.mu held: remember the lease and wake the
// router's loop so blocked devices are re-checked right away.
func (rs *RState) noteSyslogDHCP(text string, now int64) {
	ip, mac, ok := parseDHCPSyslog(text)
	if !ok || !rs.hasBlocks.Load() {
		return
	}
	if ip != "" {
		keep := rs.dhcpHints[:0]
		for _, x := range rs.dhcpHints {
			if now-x.At < hintKeep && x.IP != ip {
				keep = append(keep, x)
			}
		}
		rs.dhcpHints = append(keep, dhcpHint{IP: ip, MAC: mac, At: now})
		if len(rs.dhcpHints) > 200 {
			rs.dhcpHints = rs.dhcpHints[len(rs.dhcpHints)-200:]
		}
	}
	select {
	case rs.followWake <- struct{}{}:
	default:
	}
}

func (rs *RState) recentHints(now int64) []dhcpHint {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	var out []dhcpHint
	for _, x := range rs.dhcpHints {
		if now-x.At < hintKeep {
			out = append(out, x)
		}
	}
	return out
}

package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
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

// autoRecent counts automatic blocks in the last hour (caller holds blockMu).
func (rs *RState) autoRecent(now int64) int {
	keep := rs.autoAdds[:0]
	for _, t := range rs.autoAdds {
		if now-t < 3600_000 {
			keep = append(keep, t)
		}
	}
	rs.autoAdds = keep
	return len(keep)
}

func (rs *RState) autoRecord(now int64, n int) {
	for range n {
		rs.autoAdds = append(rs.autoAdds, now)
	}
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
	rs.autoAdds = nil
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
	rs.autoAdds = nil
	rs.mu.RLock()
	cfg := rs.cfg
	rs.mu.RUnlock()
	var eff effects
	eff.add(nowMs(), "warning", "✅", fmt.Sprintf("Đã bỏ chặn TẤT CẢ: %d thiết bị, %d IP (%d mục DrayPulse trên router) – bởi %s", len(devs), len(blocks), len(del), by), true)
	h.apply(cfg, eff)
	return len(del), nil
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

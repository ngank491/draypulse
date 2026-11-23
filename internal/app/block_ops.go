package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ---------- block / unblock (firewall rule + MAC objects, see block_fw.go) ----------

// fwSync converges the router to DrayPulse's list, with add (a key not yet
// stored) and without drop. Caller holds rs.blockMu.
func (h *Hub) fwSync(ctx context.Context, rs *RState, routerID int64, add, drop string) (*FwReport, error) {
	want, err := h.fwWantList(routerID, h.settings.blockSafety())
	if err != nil {
		return nil, err
	}
	var list []string
	for _, k := range want {
		if k != drop && k != add {
			list = append(list, k)
		}
	}
	if add != "" {
		list = append(list, add)
	}
	o, done, err := h.bindSession(ctx, rs)
	if err != nil {
		return nil, err
	}
	defer done()
	return h.fwApply(o, routerID, list)
}

// fwNote describes what a change did beyond the block itself.
func fwNote(rep *FwReport) string {
	if rep == nil {
		return ""
	}
	var n []string
	if rep.RulePlace != "" {
		n = append(n, "luật Firewall "+rep.RulePlace)
	}
	if rep.MovedUp > 0 {
		n = append(n, fmt.Sprintf("đã chuyển luật lên %d bậc, trên các luật “Pass Immediately”", rep.MovedUp))
	}
	if rep.FilterOn {
		n = append(n, "đã bật Data Filter của router")
	}
	if rep.FilterOff {
		n = append(n, "đã tắt Data Filter (DrayPulse đã bật nó)")
	}
	if len(n) == 0 {
		return ""
	}
	return " (" + strings.Join(n, "; ") + ")"
}

func (h *Hub) refreshHasBlocks(rs *RState, routerID int64) {
	n := 0
	if d, err := h.st.ListDevices(routerID); err == nil {
		n += len(d)
	}
	if b, err := h.st.ListBlocks(routerID); err == nil {
		for _, x := range b {
			if x.MAC == "" {
				n++
			}
		}
	}
	rs.hasBlocks.Store(n > 0)
}

// BlockDevice blocks a device by MAC: whatever IP it uses, its traffic to the
// Internet is dropped by the router's firewall. ip, when given, is only shown.
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
	// the router, gateways and DrayPulse's own host must keep working
	ob := h.currentObs(rs)
	ips := ob.macIPs[mac]
	if ip != "" && !slicesContains(ips, ip) {
		ips = append(ips, ip)
	}
	for _, x := range ips {
		if err := h.checkBlockTarget(rs, x); err != nil {
			return nil, fmt.Errorf("%s: %v", x, err)
		}
		if err := sf.checkIP(x, ob); err != nil {
			return nil, err
		}
	}
	rep, err := h.fwSync(ctx, rs, routerID, fwKeyMAC(mac), "")
	if err != nil {
		return nil, err
	}
	now := nowMs()
	d := Device{MAC: mac, Name: name, Host: host, Note: note, ByUser: by, At: now, MatchHost: matchHost, Origin: origin, IPs: []string{}}
	if err := h.st.AddDevice(routerID, d); err != nil {
		return nil, err
	}
	h.st.DeleteSuggestion(routerID, mac)
	rs.hasBlocks.Store(true)
	where := ""
	if len(ips) > 0 {
		where = ", đang dùng IP " + strings.Join(ips, ", ")
	}
	var eff effects
	eff.add(now, "warning", "⛔", fmt.Sprintf("Đã chặn thiết bị %s (%s%s) ra Internet theo MAC – bởi %s%s%s", firstNonEmpty(name, host, mac), mac, where, by, fwNote(rep), hostNote), false)
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
	cli.lockUrgent() // ahead of the poller's queued reads and pings
	return &bindOps{cli: cli, ctx: ctx}, func() { cli.mu.Unlock(); done() }, nil
}

// BlockClient blocks a single IP (whatever device uses it).
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
	rep, err := h.fwSync(ctx, rs, routerID, fwKeyIP(ip), "")
	if err != nil {
		return nil, err
	}
	b := Block{IP: ip, Name: name, Note: note, ByUser: by, At: nowMs()}
	if err := h.st.AddBlock(routerID, b); err != nil {
		return nil, err
	}
	rs.hasBlocks.Store(true)
	var eff effects
	eff.add(nowMs(), "warning", "⛔", fmt.Sprintf("Đã chặn IP %s ra Internet – bởi %s%s", blockLabel(b), by, fwNote(rep)), false)
	h.apply(cfg, eff)
	return &b, nil
}

func blockLabel(b Block) string {
	if b.Name != "" {
		return b.Name + " (" + b.IP + ")"
	}
	return b.IP
}

// UnblockClient removes an IP-only block.
func (h *Hub) UnblockClient(ctx context.Context, routerID int64, ip, by string) error {
	rs, cfg, err := h.unblockPrep(routerID)
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
	rep, err := h.fwSync(ctx, rs, routerID, "", fwKeyIP(ip))
	if err != nil {
		return err
	}
	if err := h.st.DeleteBlock(routerID, ip); err != nil {
		return err
	}
	h.refreshHasBlocks(rs, routerID)
	var eff effects
	eff.add(nowMs(), "info", "✅", fmt.Sprintf("Đã bỏ chặn IP %s – bởi %s%s", blockLabel(*target), by, fwNote(rep)), false)
	h.apply(cfg, eff)
	return nil
}

// UnblockDevice removes a device block.
func (h *Hub) UnblockDevice(ctx context.Context, routerID int64, mac, by string) error {
	mac = normMAC(mac)
	rs, cfg, err := h.unblockPrep(routerID)
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
	rep, err := h.fwSync(ctx, rs, routerID, "", fwKeyMAC(mac))
	if err != nil {
		return err
	}
	if err := h.st.DeleteDevice(routerID, mac); err != nil {
		return err
	}
	h.st.DeleteSuggestionsFor(routerID, mac)
	h.refreshHasBlocks(rs, routerID)
	var eff effects
	eff.add(nowMs(), "info", "✅", fmt.Sprintf("Đã bỏ chặn thiết bị %s (%s) – bởi %s%s", firstNonEmpty(target.Name, target.Host, mac), mac, by, fwNote(rep)), false)
	h.apply(cfg, eff)
	return nil
}

// followBlocks runs after every client read. The firewall rule follows a
// blocked device across IPs by itself; what is left here is the host-name
// suggestion (a new MAC with a blocked device's uncommon host name) and
// lifting the router-wide pause of 0.6.0–0.6.3.
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
	now := nowMs()
	var eff effects
	if cfg.Opts.Block.AutoPaused {
		h.saveBlockCfg(rs, func(b *BlockCfg) { b.AutoPaused, b.AutoPausedAt = false, 0 })
	}
	devs, err := h.st.ListDevices(cfg.ID)
	if err != nil || len(devs) == 0 {
		return
	}
	sf := h.settings.blockSafety()
	ob := observe(arp, lease, rs.recentHints(now)...)
	blocked := map[string]bool{}
	for _, d := range devs {
		blocked[d.MAC] = !sf.macs[d.MAC]
	}
	h.suggestByHost(cfg.ID, devs, ob, blocked, sf, now, &eff)
	h.apply(cfg, eff)
}

// reconcileBlocks converges the router to DrayPulse's list every few
// minutes: objects, groups or the rule lost (a reboot before the settings
// were saved, a change in the web UI) are put back.
func (h *Hub) reconcileBlocks(ctx context.Context, rs *RState) {
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
	now := nowMs()
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	rep, err := h.fwSync(cctx, rs, cfg.ID, "", "")
	dr := &BlockDrift{At: now, Missing: []string{}, Readded: []string{}, Released: []string{}, Extra: []string{}, Stale: []string{}}
	var eff effects
	if err != nil {
		dr.Error = err.Error()
		h.noteBlockErr(rs, &eff, now, err)
	} else {
		for _, k := range rep.Recreated {
			x := k[strings.Index(k, ":")+1:]
			dr.Missing, dr.Readded = append(dr.Missing, x), append(dr.Readded, x)
		}
		for _, k := range rep.Removed {
			dr.Extra = append(dr.Extra, k[strings.Index(k, ":")+1:])
		}
		if len(dr.Readded) > 0 || rep.MovedUp > 0 || rep.FilterOn || rep.RuleSet {
			msg := "Đối chiếu với router: "
			if len(dr.Readded) > 0 {
				msg += fmt.Sprintf("đã tạo lại cấu hình chặn cho %s", strings.Join(dr.Readded, ", "))
			} else {
				msg += "đã sửa lại luật chặn"
			}
			eff.add(now, "warning", "🔁", msg+fwNote(rep), now-rs.blockErrNotified >= 3600_000)
			if now-rs.blockErrNotified >= 3600_000 {
				rs.blockErrNotified = now
			}
		}
	}
	if err == nil {
		h.migrateLegacy(cctx, rs, cfg.ID, now, &eff)
	}
	rs.mu.Lock()
	rs.drift = dr
	rs.mu.Unlock()
	h.apply(cfg, eff)
}

// migrateLegacy: once the firewall rule blocks a device, the per-IP rows of
// 0.4–0.6 (Bind IP to MAC entries owned by a device) are removed from the
// router and the store. Caller holds rs.blockMu.
func (h *Hub) migrateLegacy(ctx context.Context, rs *RState, routerID int64, now int64, eff *effects) {
	blocks, err := h.st.ListBlocks(routerID)
	if err != nil {
		return
	}
	var legacy []Block
	for _, b := range blocks {
		if b.MAC != "" {
			legacy = append(legacy, b)
		}
	}
	if len(legacy) == 0 {
		return
	}
	o, done, err := h.bindSession(ctx, rs)
	if err != nil {
		return
	}
	n := h.legacyBindCleanup(o, rs, legacy)
	done()
	for _, b := range legacy {
		h.st.DeleteBlock(routerID, b.IP)
	}
	eff.add(now, "info", "🔁", fmt.Sprintf("Đã chuyển sang chặn bằng Firewall: bỏ %d IP chặn theo cách cũ (xoá %d mục Bind IP to MAC của DrayPulse)", len(legacy), n), false)
}

// followTick compares with the router every reconcileEvery while something
// is blocked (the firewall rule needs no per-IP following).
func (h *Hub) followTick(ctx context.Context, rs *RState, src Source, force bool) {
	if !rs.hasBlocks.Load() || time.Since(rs.lastReconcile) < reconcileEvery {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			rs.lastReconcile = time.Now()
		}
	}()
	rs.lastReconcile = time.Now()
	h.reconcileBlocks(ctx, rs)
}

// BlockInfo is the blocking summary shown with a router.
type BlockInfo struct {
	Devices      []Device     `json:"devices"`
	IPs          []Block      `json:"ips"`         // IP-only blocks (and legacy device IPs)
	Suggestions  []Suggestion `json:"suggestions"` // same host name, new MAC: waiting for an admin
	Enabled      bool         `json:"enabled"`     // blocking allowed: off still shows cleanup for leftovers
	Drift        *BlockDrift  `json:"drift,omitempty"`
	Max          int          `json:"max"` // devices/IPs per router
	AutoPaused   bool         `json:"autoPaused"`
	AutoPausedAt int64        `json:"autoPausedAt"`
}

// BlockStatus compares DrayPulse's list with the router (read-only).
type BlockStatus struct {
	Devices []Device `json:"devices"`
	Blocks  []Block  `json:"blocks"`
	On      *bool    `json:"on"`      // data filter and DrayPulse's rule both active
	Rule    string   `json:"rule"`    // where the rule sits, e.g. "1-2"
	Missing []string `json:"missing"` // blocked here, not on the router
	Extra   []string `json:"extra"`   // DrayPulse objects on the router not wanted here
	Others  int      `json:"others"`  // the admin's enabled rules in the same set
	Strict  bool     `json:"strict"`
	Raw     string   `json:"raw"`
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
	want, err := h.fwWantList(routerID, h.settings.blockSafety())
	if err != nil {
		return nil, err
	}
	chk, err := h.fwCheck(o, routerID, want)
	if err != nil {
		return nil, err
	}
	on := chk.FilterOn && chk.RuleOn
	out.On, out.Rule, out.Others = &on, chk.Rule, chk.Others
	for _, k := range chk.Missing {
		out.Missing = append(out.Missing, k[strings.Index(k, ":")+1:])
	}
	for _, k := range chk.Extra {
		out.Extra = append(out.Extra, k[strings.Index(k, ":")+1:])
	}
	return out, nil
}

// UnblockAll removes every DrayPulse block of a router: the firewall rule is
// switched off, its groups and objects cleared, the data filter switched off
// again if DrayPulse switched it on; leftovers of the Bind IP to MAC method
// (0.4–0.6) are removed too. The admin's own rules and entries stay.
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
	if _, err := h.fwApply(o, routerID, nil); err != nil {
		return 0, err
	}
	legacy := h.legacyBindCleanup(o, rs, blocks)
	if err := h.st.DeleteAllBlocks(routerID); err != nil {
		return 0, err
	}
	rs.hasBlocks.Store(false)
	rs.resetAuto()
	rs.mu.Lock()
	rs.drift = nil
	rs.mu.Unlock()
	rs.mu.RLock()
	cfg := rs.cfg
	rs.mu.RUnlock()
	n := len(devs)
	for _, b := range blocks {
		if b.MAC == "" {
			n++
		}
	}
	msg := fmt.Sprintf("Đã bỏ chặn TẤT CẢ: %d thiết bị/IP – bởi %s", n, by)
	if legacy > 0 {
		msg += fmt.Sprintf("; xoá %d mục Bind IP to MAC cũ của DrayPulse", legacy)
	}
	var eff effects
	eff.add(nowMs(), "warning", "✅", msg, true)
	h.apply(cfg, eff)
	return n, nil
}

// legacyBindCleanup removes Bind IP to MAC entries of DrayPulse 0.4–0.6 and
// their ARP lines; best effort (firmware without the command is fine).
func (h *Hub) legacyBindCleanup(o *bindOps, rs *RState, blocks []Block) int {
	st, err := o.show()
	if err != nil {
		return 0
	}
	var del []string
	for _, e := range st.Entries {
		if e.ours() && !slicesContains(del, e.IP) {
			del = append(del, e.IP)
		}
	}
	for _, b := range blocks {
		if !slicesContains(del, b.IP) {
			o.clearARP(b.IP)
		}
	}
	if len(del) > 0 {
		if err := h.bindTx(o, rs, nil, del); err != nil {
			return 0
		}
		return len(del)
	}
	rs.mu.RLock()
	wasOurs := rs.cfg.Opts.Block.TurnedOn
	rs.mu.RUnlock()
	if wasOurs && len(st.Entries) == 0 && (st.On || !st.Known) {
		if err := o.setOn(false); err == nil {
			h.saveTurnedOn(rs, false)
		}
	}
	return 0
}

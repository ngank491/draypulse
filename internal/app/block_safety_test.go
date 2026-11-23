package app

import (
	"context"
	"strings"
	"testing"
	"time"
)

// setBlockSafety changes the blocking safety settings of a test hub.
func setBlockSafety(h *Hub, protected, ignore string, max int) {
	h.settings.mu.Lock()
	defer h.settings.mu.Unlock()
	h.settings.cur.BlockProtected = protected
	if ignore != "" {
		h.settings.cur.BlockHostIgnore = ignore
	}
	if max > 0 {
		h.settings.cur.BlockAutoMax = max
	}
}

func eventText(t *testing.T, st *Store) string {
	t.Helper()
	evs, _ := st.ListEvents(nil, 100)
	all := ""
	for _, e := range evs {
		all += e.Msg + "\n"
	}
	return all
}

func (b *simBindMAC) ips() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var l []string
	for _, e := range b.entries {
		l = append(l, e.IP)
	}
	return l
}

func TestGenericHostNames(t *testing.T) {
	sf := (*SettingsStore)(nil).blockSafety()
	for _, g := range []string{"iPhone", "IPAD", "android-5f2a9c", "Galaxy-A54", "Redmi-12", "redmi", "OPPO-A78", "vivo-Y36", "", " ", "pc", "iPhone-2"} {
		if !sf.genericHost(g) {
			t.Errorf("%q must be generic", g)
		}
	}
	for _, ok := range []string{"May-Ke-Toan-03", "iPhone-cua-Lan", "LAPTOP-GD", "A23-cua-the", "DESKTOP-7K2L9QF"} {
		if sf.genericHost(ok) {
			t.Errorf("%q must not be generic", ok)
		}
	}
	if p, err := normHostPatterns("iPhone, Redmi-*\nGALAXY-?"); err != nil || p != "iphone, redmi-*, galaxy-?" {
		t.Fatalf("%q %v", p, err)
	}
	if _, err := normHostPatterns("bad[pattern"); err == nil {
		t.Fatal("broken pattern must be refused")
	}
	if p, err := normProtected("aa-bb-cc-dd-ee-ff; 192.168.1.10\n AA:BB:CC:DD:EE:FF"); err != nil || p != "AA:BB:CC:DD:EE:FF, 192.168.1.10" {
		t.Fatalf("%q %v", p, err)
	}
	if _, err := normProtected("printer"); err == nil {
		t.Fatal("non MAC/IP must be refused")
	}
}

func TestSettingsBlockSafetyUpdate(t *testing.T) {
	h, _, _ := newClientHub(t)
	if g := h.settings.Get(); g.BlockAutoMax != 10 || !strings.Contains(g.BlockHostIgnore, "redmi-*") {
		t.Fatalf("defaults %+v", g)
	}
	base := SettingsInput{SummaryAt: "08:00", RepeatMin: 30, Timezone: "Asia/Ho_Chi_Minh", RetentionDays: 30}
	in := base
	prot, max := "aa:bb:cc:dd:ee:01, 192.168.1.9", 3
	in.BlockProtected, in.BlockAutoMax = &prot, &max
	if err := h.settings.Update(in); err != nil {
		t.Fatal(err)
	}
	if g := h.settings.Get(); g.BlockAutoMax != 3 || g.BlockProtected != "AA:BB:CC:DD:EE:01, 192.168.1.9" || !strings.Contains(g.BlockHostIgnore, "iphone") {
		t.Fatalf("after update %+v", g)
	}
	// an older form that does not send the fields keeps them
	if err := h.settings.Update(base); err != nil || h.settings.Get().BlockAutoMax != 3 {
		t.Fatalf("keep: %v %+v", err, h.settings.Get())
	}
	bad := 0
	in.BlockAutoMax = &bad
	if err := h.settings.Update(in); err == nil {
		t.Fatal("limit 0 must be refused")
	}
}

// The incident of v0.5.0: one block cascaded to hundreds of phones sharing a
// factory host name. Host names now only suggest, generic ones never match.
func TestHostNameOnlySuggests(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := h.get(r.ID)
	const A, B, C, D = "7E:48:A0:00:00:01", "7E:48:A0:00:00:02", "7E:48:A0:00:00:03", "7E:48:A0:00:00:04"

	// a generic name: blocked by MAC only, never followed by name
	d, err := h.BlockDevice(ctx, r.ID, A, "192.168.1.30", "", "Redmi-12", "", true, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if d.MatchHost {
		t.Fatal("a generic host name must not be followed")
	}
	if !strings.Contains(eventText(t, st), "tên này phổ biến") {
		t.Fatal("the admin must be told why")
	}
	var lease []Row
	for i := range 50 {
		lease = append(lease, Row{"address": "192.168.1." + itoaInt(100+i), "mac-address": "02:00:00:00:01:" + hex2(i), "host-name": "Redmi-12"})
	}
	n := len(bm.Log)
	h.followBlocks(ctx, rs, nil, lease)
	if devs, _ := st.ListDevices(r.ID); len(devs) != 1 || len(bm.Log) != n {
		t.Fatalf("50 phones named Redmi-12 must stay untouched: %d devices, %v", len(devs), bm.Log[n:])
	}
	if s, _ := st.ListSuggestions(r.ID, true); len(s) != 0 {
		t.Fatalf("no suggestion for a generic name: %+v", s)
	}

	// an uncommon name: one new MAC → one suggestion and one alert, nothing blocked
	if _, err := h.BlockDevice(ctx, r.ID, B, "192.168.1.31", "Máy lạ", "Kho-Tablet-2", "", true, "admin"); err != nil {
		t.Fatal(err)
	}
	n = len(bm.Log)
	same := []Row{{"address": "192.168.1.32", "mac-address": C, "host-name": "kho-tablet-2"}}
	h.followBlocks(ctx, rs, nil, same)
	h.followBlocks(ctx, rs, nil, same) // repeated reads do not repeat the alert
	if len(bm.Log) != n {
		t.Fatalf("suggestion must not touch the router: %v", bm.Log[n:])
	}
	if s, _ := st.ListSuggestions(r.ID, false); len(s) != 1 || s[0].MAC != C {
		t.Fatalf("suggestions %+v", s)
	}
	if c := strings.Count(eventText(t, st), "MAC mới "+C); c != 1 {
		t.Fatalf("want exactly one alert, got %d", c)
	}
	// dismissed: never suggested again
	if err := h.DismissSuggestion(r.ID, C, "admin"); err != nil {
		t.Fatal(err)
	}
	h.followBlocks(ctx, rs, nil, same)
	if s, _ := st.ListSuggestions(r.ID, false); len(s) != 0 {
		t.Fatalf("dismissed suggestion came back: %+v", s)
	}
	if _, err := h.AcceptSuggestion(ctx, r.ID, C, "admin"); err == nil {
		t.Fatal("a dismissed suggestion cannot be accepted")
	}
	// two unblocked MACs with the same name at once: ambiguous, no suggestion
	h.followBlocks(ctx, rs, nil, []Row{{"address": "192.168.1.33", "mac-address": D, "host-name": "Kho-Tablet-2"},
		{"address": "192.168.1.34", "mac-address": "7E:48:A0:00:00:05", "host-name": "Kho-Tablet-2"}})
	if s, _ := st.ListSuggestions(r.ID, true); len(s) != 1 {
		t.Fatalf("ambiguous name must not be suggested: %+v", s)
	}
	// unblocking the device forgets its suggestions
	if err := h.UnblockDevice(ctx, r.ID, B, "admin"); err != nil {
		t.Fatal(err)
	}
	if s, _ := st.ListSuggestions(r.ID, true); len(s) != 0 {
		t.Fatalf("suggestions of an unblocked device must go: %+v", s)
	}
}

// The hourly limit counts the new IPs of one device (Bind IP to MAC makes a
// blocked device hop between IPs). A device over the limit is not followed
// for the hour; other devices are, and nothing pauses router-wide.
func TestAutoBlockLimitPerDevice(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := h.get(r.ID)
	setBlockSafety(h, "", "", 2)
	const A, B = "3C:52:82:00:00:0A", "3C:52:82:00:00:0B"
	for _, m := range []string{A, B} {
		if _, err := h.BlockDevice(ctx, r.ID, m, "", "", "", "", false, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	two := []Row{{"address": "192.168.1.50", "mac-address": A}, {"address": "192.168.1.51", "mac-address": A}}
	h.followBlocks(ctx, rs, two, nil)
	if got := bm.ips(); len(got) != 2 {
		t.Fatalf("within the limit: %v", got)
	}
	// a third IP for A within the hour is over the limit; B is still followed
	more := append(two, Row{"address": "192.168.1.52", "mac-address": A}, Row{"address": "192.168.1.60", "mac-address": B})
	h.followBlocks(ctx, rs, more, nil)
	got := bm.ips()
	if len(got) != 3 || slicesContains(got, "192.168.1.52") || !slicesContains(got, "192.168.1.60") {
		t.Fatalf("A over its limit, B followed: %v", got)
	}
	if r2, _ := st.GetRouter(r.ID); r2.Opts.Block.AutoPaused {
		t.Fatal("no router-wide pause any more")
	}
	if c := strings.Count(eventText(t, st), "đã đổi IP 2 lần"); c != 1 {
		t.Fatalf("one warning per device and hour, got %d", c)
	}
	h.followBlocks(ctx, rs, more, nil) // no repeated warning
	if c := strings.Count(eventText(t, st), "đã đổi IP 2 lần"); c != 1 {
		t.Fatalf("repeated warning: %d", c)
	}
	// manual blocks are not limited
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.90", "", "", "", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := h.ResumeAuto(r.ID, "admin"); err != nil { // the admin can reset the counters
		t.Fatal(err)
	}
	h.followBlocks(ctx, rs, more, nil)
	if got := bm.ips(); !slicesContains(got, "192.168.1.52") {
		t.Fatalf("after reset: %v", got)
	}
}

// The pause of 0.6.0–0.6.3 is lifted on the first follow after an upgrade.
func TestLegacyPauseLifted(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := h.get(r.ID)
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:0C", "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	h.saveBlockCfg(rs, func(b *BlockCfg) { b.AutoPaused, b.AutoPausedAt = true, 1 })
	h.followBlocks(ctx, rs, []Row{{"address": "192.168.1.70", "mac-address": "3C:52:82:00:00:0C"}}, nil)
	if r2, _ := st.GetRouter(r.ID); r2.Opts.Block.AutoPaused {
		t.Fatal("legacy pause must be lifted")
	}
	if got := bm.ips(); len(got) != 1 || got[0] != "192.168.1.70" {
		t.Fatalf("device followed again: %v", got)
	}
}

// A blocked device that got another IP: the old IP is released (with its
// ARP entry), so one device holds one entry instead of one per hop.
func TestReleaseOldIPWhenDeviceMoves(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := h.get(r.ID)
	const A = "3C:52:82:00:00:0D"
	if _, err := h.BlockDevice(ctx, r.ID, A, "192.168.1.80", "Phone", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	h.followBlocks(ctx, rs, nil, []Row{{"address": "192.168.1.81", "mac-address": A}})
	if got := bm.ips(); len(got) != 1 || got[0] != "192.168.1.81" {
		t.Fatalf("old IP must be released, new one blocked: %v", got)
	}
	if !slicesContains(bm.ArpDel, "192.168.1.80") {
		t.Fatalf("ARP entry of the released IP must be cleared: %v", bm.ArpDel)
	}
	if l, _ := st.ListBlocks(r.ID); len(l) != 1 || l[0].IP != "192.168.1.81" {
		t.Fatalf("store: %+v", l)
	}
	if !strings.Contains(eventText(t, st), "Phone đã chuyển sang IP 192.168.1.81") {
		t.Fatalf("events:\n%s", eventText(t, st))
	}
}

// A failing block must not undo a release done in the same follow: the
// innocent device on the released IP would be cut off again.
func TestFailedBlockKeepsRelease(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := h.get(r.ID)
	const A, M = "3C:52:82:00:00:0E", "F0:2F:74:00:00:0E"
	if _, err := h.BlockDevice(ctx, r.ID, A, "192.168.1.90", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	bm.mu.Lock()
	bm.IgnoreAdd = true // the router stops storing new entries
	bm.mu.Unlock()
	h.followBlocks(ctx, rs, []Row{{"address": "192.168.1.90", "mac-address": M}, {"address": "192.168.1.91", "mac-address": A}}, nil)
	if got := bm.ips(); len(got) != 0 {
		t.Fatalf("the release must stay done: %v", got)
	}
	for range 3 {
		h.followBlocks(ctx, rs, []Row{{"address": "192.168.1.91", "mac-address": A}}, nil)
	}
	if c := strings.Count(eventText(t, st), "Không cập nhật được danh sách chặn"); c != 1 {
		t.Fatalf("a repeated failure must be reported once, got %d", c)
	}
}

// Comparison with the router: entries the router dropped are added again
// while still used, released otherwise; stray DrayPulse entries and ARP
// lines pointing at the blocking MAC are removed.
func TestReconcileBlocks(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := h.get(r.ID)
	const A, B = "3C:52:82:00:00:1A", "3C:52:82:00:00:1B"
	if _, err := h.BlockDevice(ctx, r.ID, A, "192.168.1.100", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BlockDevice(ctx, r.ID, B, "192.168.1.101", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.102", "", "", "", "admin"); err != nil {
		t.Fatal(err)
	}
	// the router loses everything, and holds an entry DrayPulse does not know
	bm.mu.Lock()
	bm.entries = []bindEntry{{IP: "192.168.1.103", MAC: blockMAC, Comment: "DrayPulse"}}
	bm.mu.Unlock()
	arp := []Row{
		{"address": "192.168.1.100", "mac-address": A},        // A still there
		{"address": "192.168.1.104", "mac-address": blockMAC}, // stale ARP line
	} // B is gone from 192.168.1.101
	h.reconcileBlocks(ctx, rs, arp, nil)
	got := bm.ips()
	if len(got) != 2 || !slicesContains(got, "192.168.1.100") || !slicesContains(got, "192.168.1.102") {
		t.Fatalf("re-added A's and the manual IP; removed the stray entry: %v", got)
	}
	if l, _ := st.ListBlocks(r.ID); len(l) != 2 {
		t.Fatalf("B's old IP must be released in the store: %+v", l)
	}
	for _, ip := range []string{"192.168.1.101", "192.168.1.103", "192.168.1.104"} {
		if !slicesContains(bm.ArpDel, ip) {
			t.Errorf("ARP of %s must be cleared: %v", ip, bm.ArpDel)
		}
	}
	rs.mu.RLock()
	dr := rs.drift
	rs.mu.RUnlock()
	if dr == nil || len(dr.Missing) != 3 || len(dr.Readded) != 2 || len(dr.Released) != 1 || len(dr.Extra) != 1 || len(dr.Stale) != 1 {
		t.Fatalf("drift %+v", dr)
	}
	if !strings.Contains(eventText(t, st), "3 mục chặn đã mất khỏi router") {
		t.Fatalf("events:\n%s", eventText(t, st))
	}
	// in sync: nothing to do, no event
	n, before := len(bm.Log), strings.Count(eventText(t, st), "Đối chiếu với router")
	h.reconcileBlocks(ctx, rs, []Row{{"address": "192.168.1.100", "mac-address": A}}, nil)
	if after := strings.Count(eventText(t, st), "Đối chiếu với router"); after != before || len(bm.Log) != n {
		t.Fatalf("in sync must stay quiet: %v", bm.Log[n:])
	}
}

// Switching blocking off keeps leftovers visible and removable.
func TestUnblockWhenBlockingDisabled(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := h.get(r.ID)
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:2A", "192.168.1.110", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.111", "", "", "", "admin"); err != nil {
		t.Fatal(err)
	}
	r2, _ := st.GetRouter(r.ID)
	r2.Opts.Block.Enabled = false
	st.SaveRouter(r2)
	rs.mu.Lock()
	rs.cfg.Opts.Block.Enabled = false
	rs.mu.Unlock()
	if v := h.view(rs, true); v.Blocking == nil || v.Blocking.Enabled || len(v.Blocking.IPs) != 2 {
		t.Fatalf("leftovers must stay visible: %+v", v.Blocking)
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.112", "", "", "", "admin"); err == nil {
		t.Fatal("new blocks need blocking enabled")
	}
	if err := h.UnblockClient(ctx, r.ID, "192.168.1.111", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := h.UnblockDevice(ctx, r.ID, "3C:52:82:00:00:2A", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := bm.ips(); len(got) != 0 || !slicesContains(bm.ArpDel, "192.168.1.110") {
		t.Fatalf("router %v arp %v", got, bm.ArpDel)
	}
}

func TestProtectedNeverBlocked(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := h.get(r.ID)
	const P, A = "00:11:32:AA:BB:CC", "3C:52:82:00:00:0B"
	setBlockSafety(h, P+", 192.168.1.10", "", 0)
	rs.mu.Lock()
	rs.Sections["arp"] = []Row{{"address": "192.168.1.11", "mac-address": P}}
	rs.mu.Unlock()
	if _, err := h.BlockDevice(ctx, r.ID, P, "", "", "", "", false, "admin"); err == nil || !strings.Contains(err.Error(), "Không bao giờ chặn") {
		t.Fatalf("protected MAC: %v", err)
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.10", "", "", "", "admin"); err == nil {
		t.Fatal("protected IP must be refused")
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.11", "", "", "", "admin"); err == nil {
		t.Fatal("an IP used by a protected MAC must be refused")
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.12", strings.ToLower(P), "", "", "admin"); err == nil {
		t.Fatal("a protected MAC given with the IP must be refused")
	}
	// a blocked device never gets a protected IP
	if _, err := h.BlockDevice(ctx, r.ID, A, "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	h.followBlocks(ctx, rs, []Row{{"address": "192.168.1.10", "mac-address": A}, {"address": "192.168.1.20", "mac-address": A}}, nil)
	if got := bm.ips(); len(got) != 1 || got[0] != "192.168.1.20" {
		t.Fatalf("protected IP must be skipped: %v", got)
	}
	if len(bm.Log) == 0 {
		t.Fatal("expected router writes")
	}
	// the device is added to the protected list later: its IPs are released
	setBlockSafety(h, P+", 192.168.1.10, "+A, "", 0)
	h.followBlocks(ctx, rs, []Row{{"address": "192.168.1.20", "mac-address": A}}, nil)
	if got := bm.ips(); len(got) != 0 {
		t.Fatalf("protected device must be released: %v", got)
	}
	if !strings.Contains(eventText(t, st), "Nhả chặn IP 192.168.1.20") {
		t.Fatal("release event missing")
	}
}

// IP reuse: the DHCP table already gives the blocked IP to another device
// while ARP still shows the blocked one. Release at once, and do not block
// the IP again while both are seen (no flapping).
func TestReleaseOnIPReuse(t *testing.T) {
	bm := &simBindMAC{}
	h, r, _ := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := h.get(r.ID)
	const A, M = "3C:52:82:00:00:0C", "F0:2F:74:00:00:0D"
	if _, err := h.BlockDevice(ctx, r.ID, A, "192.168.1.60", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	arp := []Row{{"address": "192.168.1.60", "mac-address": A}}   // stale
	lease := []Row{{"address": "192.168.1.60", "mac-address": M}} // the new owner
	h.followBlocks(ctx, rs, arp, lease)
	if got := bm.ips(); len(got) != 0 {
		t.Fatalf("reused IP must be released: %v", got)
	}
	n := len(bm.Log)
	h.followBlocks(ctx, rs, arp, lease)
	if len(bm.Log) != n {
		t.Fatalf("must not block the shared IP again: %v", bm.Log[n:])
	}
	// blocking by MAC with an IP that belongs to someone else is refused
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:0E", "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	rs.mu.Lock()
	rs.Sections["arp"] = []Row{{"address": "192.168.1.61", "mac-address": M}}
	rs.mu.Unlock()
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:0F", "192.168.1.61", "", "", "", false, "admin"); err == nil || !strings.Contains(err.Error(), M) {
		t.Fatalf("want refusal naming the current owner, got %v", err)
	}
}

func TestParseDHCPSyslog(t *testing.T) {
	cases := []struct {
		line, ip, mac string
		ok            bool
	}{
		{"DHCP server: assigned 192.168.1.50 to 00-1e-c2-aa-bb-cc", "192.168.1.50", "00:1E:C2:AA:BB:CC", true},
		{"[DHCP] ACK IP:192.168.20.7 MAC:7e:48:a0:68:b9:52 Host:Redmi-12", "192.168.20.7", "7E:48:A0:68:B9:52", true},
		{"DHCP request from 7e:48:a0:68:b9:52", "", "", true},                             // no IP: wake only
		{"DHCP server 192.168.1.1 offers 192.168.1.9 to 7e:48:a0:68:b9:52", "", "", true}, // two IPs: ambiguous
		{"DHCP lease 8.8.8.8 to 7e:48:a0:68:b9:52", "", "", true},                         // public IP is not a LAN lease
		{"WAN1 DHCP client got 100.64.1.2", "", "", false},                                // no lease keyword… "got" is not one
		{"Admin login from 192.168.1.20 00:11:22:33:44:55", "", "", false},                // not DHCP
	}
	for _, c := range cases {
		ip, mac, ok := parseDHCPSyslog(c.line)
		if ip != c.ip || mac != c.mac || ok != c.ok {
			t.Errorf("%q → %q %q %v", c.line, ip, mac, ok)
		}
	}
}

// A DHCP lease in syslog wakes the router's loop: the reused IP is released
// within seconds, without waiting for the next poll.
func TestSyslogDHCPReleasesAtOnce(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const A = "3C:52:82:00:00:10"
	if _, err := h.BlockDevice(ctx, r.ID, A, "192.168.1.70", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	rs := h.get(r.ID)
	h.observeSyslog(r.ID, syslogMsg{Facility: "user", Text: "DHCP server: assigned 192.168.1.70 to f0-2f-74-00-00-11"}, nowMs(), &syslogServer{lastMsg: map[int64]map[string]int64{}, perMin: map[int64]int{}})
	select {
	case <-rs.followWake: // the router's loop would run followTick(force) now
	default:
		t.Fatal("a DHCP lease in syslog must wake the follow loop")
	}
	// followTick(force) re-reads ARP/DHCP (the simulator knows neither) and applies the syslog lease
	rs.mu.RLock()
	cfg := rs.cfg
	rs.mu.RUnlock()
	src, err := h.source(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer src.(*draytekSource).Close()
	h.followTick(ctx, rs, src, true)
	if got := bm.ips(); len(got) != 0 {
		t.Fatalf("syslog lease did not release the IP: %v", got)
	}
	// a lease line for a blocked device's own MAC never blocks anything new
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:12", "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	rs.mu.Lock()
	rs.noteSyslogDHCP("DHCP ACK 192.168.1.71 3c-52-82-00-00-12", nowMs())
	rs.mu.Unlock()
	h.followBlocks(ctx, rs, nil, nil)
	if got := bm.ips(); len(got) != 0 {
		t.Fatalf("syslog must not add blocks: %v", got)
	}
	if l, _ := st.ListBlocks(r.ID); len(l) != 0 {
		t.Fatalf("store: %+v", l)
	}
}

func TestUnblockAll(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:20", "192.168.1.80", "", "Kho-PC-9", "", true, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:21", "192.168.1.81", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.82", "", "", "", "admin"); err != nil {
		t.Fatal(err)
	}
	st.AddSuggestion(r.ID, Suggestion{MAC: "3C:52:82:00:00:22", RefMAC: "3C:52:82:00:00:20", At: 1})
	// an entry the admin adds while the function is on must survive
	bm.mu.Lock()
	bm.entries = append(bm.entries, bindEntry{IP: "192.168.1.5", MAC: "00:50:7F:22:33:55", Comment: "printer"})
	bm.mu.Unlock()
	n, err := h.UnblockAll(ctx, r.ID, "admin")
	if err != nil || n != 3 {
		t.Fatalf("%d %v", n, err)
	}
	if got := bm.ips(); len(got) != 1 || got[0] != "192.168.1.5" || !bm.on {
		t.Fatalf("admin entry and ON state must remain: %v on=%v", got, bm.on)
	}
	d, _ := st.ListDevices(r.ID)
	b, _ := st.ListBlocks(r.ID)
	s, _ := st.ListSuggestions(r.ID, true)
	if len(d)+len(b)+len(s) != 0 || h.get(r.ID).hasBlocks.Load() {
		t.Fatalf("store must be empty: %v %v %v", d, b, s)
	}
	if !strings.Contains(eventText(t, st), "Đã bỏ chặn TẤT CẢ: 2 thiết bị, 3 IP") {
		t.Fatalf("event:\n%s", eventText(t, st))
	}
	// without the admin's entry the function goes off again (DrayPulse turned it on)
	bm.mu.Lock()
	bm.entries = nil
	bm.mu.Unlock()
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.83", "", "", "", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UnblockAll(ctx, r.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if bm.on || len(bm.ips()) != 0 {
		t.Fatal("DrayPulse switched the function on, so unblock-all must switch it off")
	}
	if r2, _ := st.GetRouter(r.ID); r2.Opts.Block.TurnedOn {
		t.Fatal("TurnedOn must be cleared")
	}
	for _, c := range bm.Log {
		if !cliWriteCommandAllowed(c) {
			t.Fatalf("command outside the allowlist: %q", c)
		}
	}
}

// A blocking transaction keeps the router's CLI session for all of its
// commands: the poller's reads and pings wait instead of interleaving.
func TestBindSessionHoldsCLI(t *testing.T) {
	bm := &simBindMAC{}
	h, r, _ := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	o, done, err := h.bindSession(ctx, h.get(r.ID))
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() { o.cli.Run(ctx, "sys version"); close(finished) }()
	if _, err := o.show(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
		t.Fatal("another command ran in the middle of the transaction")
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := o.show(); err != nil {
		t.Fatal(err)
	}
	done()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting command must run once the transaction ends")
	}
}

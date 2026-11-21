package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// blockHarness runs a hub with one pull router whose CLI is a simulated
// DrayOS with a Bind IP to MAC table.
func blockHarness(t *testing.T, bm *simBindMAC) (*Hub, *Router, *Store) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	sim, err := startSimCLI(ctx, "Vigor", "admin", "pw", func(cmd string) string {
		if out, ok := bm.handle(cmd); ok {
			return out
		}
		return "% Unknown command"
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	st, _ := OpenStore(filepath.Join(dir, "db"))
	box, _ := LoadBox(filepath.Join(dir, "key"))
	settings, _ := NewSettingsStore(st, box)
	h := NewHub(st, box, settings, false)
	r := &Router{Name: "R", Mode: "pull", Host: "127.0.0.1", Username: "admin", Interval: 300, WANTarget: "8.8.8.8",
		Opts: DrayOpts{SNMPVersion: "off", CLI: "telnet", CLIPort: sim.Port(), Block: BlockCfg{Enabled: true}}}
	r.secret = box.Seal("pw")
	if err := st.SaveRouter(r); err != nil {
		t.Fatal(err)
	}
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// the router's LAN, as the poller would have read it
	rs := h.get(r.ID)
	rs.mu.Lock()
	rs.Sections["lan"] = []Row{{"name": "LAN1", "enabled": "true", "address": "192.168.1.1", "gateway": "192.168.1.1", "network": "192.168.1.0/24"}}
	rs.mu.Unlock()
	t.Cleanup(func() { cancel(); h.Wait(); st.Close() })
	return h, r, st
}

func TestParseBindMAC(t *testing.T) {
	st := parseBindMAC("> ip bindmac show\nip bind mac function is turned OFF\nip bind mac function is STRICT OFF\nShow all IP Bind MAC entries.\nIP : 192.168.1.46 bind MAC : 00-50-7f-22-33-55 HOST ID :              \nComment : just\n")
	if !st.Known || st.On || st.Strict || len(st.Entries) != 1 || st.Entries[0].IP != "192.168.1.46" || st.Entries[0].MAC != "00:50:7F:22:33:55" || st.Entries[0].Comment != "just" {
		t.Fatalf("%+v", st)
	}
	// Vigor 3912S 4.4.3.2: comment on the same line as the entry (real output)
	one := parseBindMAC("ip bind mac function is turned ON\nip bind mac function is STRICT OFF\nShow all IP Bind MAC entries.\nIP : 192.168.31.246 bind MAC : 02-dd-00-00-00-01 HOST ID : Comment : DrayPulse\n")
	if !one.Known || !one.On || len(one.Entries) != 1 || one.Entries[0].Comment != "DrayPulse" || !one.Entries[0].ours() {
		t.Fatalf("same-line comment: %+v", one)
	}
	// a host id between, and an entry without any comment
	two := parseBindMAC("IP : 192.168.31.10 bind MAC : 00-50-7f-22-33-55 HOST ID : nas Comment : kho\nIP : 192.168.31.11 bind MAC : 02-dd-00-00-00-01 HOST ID :\n")
	if len(two.Entries) != 2 || two.Entries[0].Comment != "kho" || two.Entries[0].ours() || !two.Entries[1].ours() {
		t.Fatalf("variants: %+v", two)
	}
	if parseBindMAC("% Unknown command").Known {
		t.Fatal("unknown output must not look like a state")
	}
}

func TestBlockUnblockFlow(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for _, bad := range []string{"192.168.1.1", "8.8.8.8", "10.9.9.9", "x"} {
		if _, err := h.BlockClient(ctx, r.ID, bad, "", "", "", "admin"); err == nil {
			t.Fatalf("must refuse %s", bad)
		}
	}
	b, err := h.BlockClient(ctx, r.ID, "192.168.1.21", "f0-2f-74-55-00-21", "LAPTOP-GD", "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !bm.on || len(bm.entries) != 1 || bm.entries[0].MAC != blockMAC || bm.entries[0].Comment != "DrayPulse" || b.MAC != "" { // IP-only block: owned by no device
		t.Fatalf("router state %+v %+v", bm, b)
	}
	if r2, _ := st.GetRouter(r.ID); !r2.Opts.Block.TurnedOn {
		t.Fatal("TurnedOn must be remembered")
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.21", "", "", "", "admin"); err == nil {
		t.Fatal("double block must fail")
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.22", "", "", "", "admin"); err != nil {
		t.Fatal(err)
	}
	live, _ := h.BlockState(ctx, r.ID, true)
	if live.On == nil || !*live.On || len(live.Missing) != 0 || len(live.Extra) != 0 || len(live.Blocks) != 2 {
		t.Fatalf("live %+v", live)
	}
	if err := h.UnblockClient(ctx, r.ID, "192.168.1.21", "admin"); err != nil {
		t.Fatal(err)
	}
	if !bm.on || len(bm.entries) != 1 {
		t.Fatal("function must stay on while another IP is blocked")
	}
	if err := h.UnblockClient(ctx, r.ID, "192.168.1.22", "admin"); err != nil {
		t.Fatal(err)
	}
	if bm.on || len(bm.entries) != 0 {
		t.Fatal("DrayPulse switched the function on, so it must switch it off again")
	}
	evs, _ := st.ListEvents(nil, 20)
	all := ""
	for _, e := range evs {
		all += e.Msg + "\n"
	}
	if !strings.Contains(all, "Đã chặn IP LAPTOP-GD (192.168.1.21) khỏi mạng – bởi admin") || !strings.Contains(all, "Đã bỏ chặn") {
		t.Fatalf("events:\n%s", all)
	}
	for _, c := range bm.Log {
		if !strings.HasPrefix(c, "ip bindmac ") || strings.Contains(c, "all") || strings.Contains(c, "strict") {
			t.Fatalf("unexpected command %q", c)
		}
	}
}

func TestBlockRespectsUserEntries(t *testing.T) {
	bm := &simBindMAC{entries: []bindEntry{{IP: "192.168.1.50", MAC: "00:50:7F:22:33:55", Comment: "printer"}}}
	h, r, _ := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// function off with the admin's own entry: switching on would enforce it, so refuse
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.21", "", "", "", "admin"); err == nil || !strings.Contains(err.Error(), "192.168.1.50") {
		t.Fatalf("want refusal naming the user entry, got %v", err)
	}
	if bm.on || len(bm.Log) != 0 {
		t.Fatal("nothing may change")
	}
	// with the function already on, blocking works and leaves it on afterwards
	bm.on = true
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.21", "", "", "", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.50", "", "", "", "admin"); err == nil {
		t.Fatal("an IP the admin bound must not be touched")
	}
	if err := h.UnblockClient(ctx, r.ID, "192.168.1.21", "admin"); err != nil {
		t.Fatal(err)
	}
	if !bm.on || len(bm.entries) != 1 || bm.entries[0].IP != "192.168.1.50" {
		t.Fatalf("the admin's entry and the ON state must remain: %+v", bm)
	}
}

func TestBlockUndoWhenRouterIgnoresAdd(t *testing.T) {
	bm := &simBindMAC{IgnoreAdd: true}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.21", "", "", "", "admin"); err == nil {
		t.Fatal("want error when the entry is not stored")
	}
	if bm.on {
		t.Fatal("the function must be switched back off")
	}
	if l, _ := st.ListBlocks(r.ID); len(l) != 0 {
		t.Fatal("nothing may be recorded")
	}
}

func TestBlockWriteAllowlist(t *testing.T) {
	for _, ok := range []string{"ip bindmac show", "ip bindmac on", "ip bindmac off", "ip bindmac add 192.168.1.21 02:dd:00:00:00:01 DrayPulse", "ip bindmac del 192.168.1.21"} {
		if !cliWriteCommandAllowed(ok) {
			t.Error("should allow", ok)
		}
		if cliCommandAllowed(ok) {
			t.Error("read-only list must not contain", ok)
		}
	}
	for _, bad := range []string{"ip bindmac del all", "ip bindmac strict_on", "ip bindmac add 192.168.1.21 aa:bb:cc:dd:ee:ff DrayPulse",
		"ip bindmac add 192.168.1.21 02:dd:00:00:00:01 other", "ip bindmac subnet clear", "ip bindmac on; sys reboot", "sys reboot"} {
		if cliWriteCommandAllowed(bad) {
			t.Error("should block", bad)
		}
	}
}

func TestVlanEventsAndPool(t *testing.T) {
	h, rs, st := newClientHub(t)
	now := nowMs()
	v1 := parseVlanStatus(fixture(t, "vlan_status.txt"))
	h.observeSection(rs, "vlan", v1, now)
	moved := parseVlanStatus(strings.Replace(fixture(t, "vlan_status.txt"), "  1    ON    20   2           V           V ", "  1    ON    20   2        V              V ", 1))
	h.observeSection(rs, "vlan", moved, now+1)
	h.observeSection(rs, "lan", parseShowLan(fixture(t, "show_lan.txt")), now+2)
	var leases []Row
	for i := range 46 { // LAN2 pool is 50
		leases = append(leases, Row{"address": "192.168.20." + itoaInt(10+i), "mac-address": "02:00:00:00:00:" + hex2(i), "server": "LAN2", "status": "bound"})
	}
	h.observeSection(rs, "lease", leases, now+3)
	evs, _ := st.ListEvents(nil, 10)
	all := ""
	for _, e := range evs {
		all += e.Msg + "\n"
	}
	if !strings.Contains(all, "VLAN 1 đổi cấu hình: VID 20, p4,s2, LAN2 → VID 20, p3,s2, LAN2") || !strings.Contains(all, "DHCP LAN2 sắp hết địa chỉ: 46/50 (92%)") {
		t.Fatalf("events:\n%s", all)
	}
	rs.mu.RLock()
	vl, lans := rs.vlanViews()
	rs.mu.RUnlock()
	if len(vl) != 3 || vl[1].Subnet != "LAN2" || vl[1].Network != "192.168.20.0/24" || vl[1].Leases != 46 || vl[1].PoolSize != 50 {
		t.Fatalf("vlan views %+v", vl)
	}
	if len(lans) != 3 || lans[0].Name != "LAN1" || len(lans[1].Vlans) != 1 {
		t.Fatalf("lan views %+v", lans)
	}
}

func itoaInt(i int) string { return strconv.Itoa(i) }

func hex2(i int) string { return fmt.Sprintf("%02X", i) }

func TestBlockDeviceFollowsItsIPs(t *testing.T) {
	bm := &simBindMAC{}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := h.get(r.ID)
	const A, B, C = "A4:C6:9A:00:00:23", "3C:52:82:11:22:33", "DA:11:22:33:44:55"
	rs.mu.Lock()
	rs.Sections["arp"] = []Row{{"address": "192.168.1.21", "mac-address": A, "host": "Galaxy-S24"}}
	rs.mu.Unlock()

	if _, err := h.BlockDevice(ctx, r.ID, A, "", "Điện thoại lạ", "Galaxy-S24", "", true, "admin"); err != nil {
		t.Fatal(err)
	}
	ips := func() []string {
		var l []string
		for _, e := range bm.entries {
			l = append(l, e.IP)
		}
		return l
	}
	if got := ips(); len(got) != 1 || got[0] != "192.168.1.21" || !bm.on {
		t.Fatalf("initial block %v", got)
	}
	// DHCP hands the blocked phone a new address: it must be blocked too
	h.followBlocks(ctx, rs, nil, []Row{{"address": "192.168.1.40", "mac-address": A, "host-name": "Galaxy-S24"}})
	if got := ips(); len(got) != 2 || got[1] != "192.168.1.40" {
		t.Fatalf("new IP not followed: %v", got)
	}
	// the router may show the blocking MAC for a blocked IP: never treat that as another device
	h.followBlocks(ctx, rs, []Row{{"address": "192.168.1.40", "mac-address": blockMAC}}, nil)
	if len(ips()) != 2 {
		t.Fatal("blocking MAC in ARP must be ignored")
	}
	// the old address now belongs to an innocent device: release it
	h.followBlocks(ctx, rs, []Row{{"address": "192.168.1.21", "mac-address": B}}, nil)
	if got := ips(); len(got) != 1 || got[0] != "192.168.1.40" {
		t.Fatalf("old IP not released: %v", got)
	}
	// the phone randomises its MAC but keeps its host name: block the new MAC
	h.followBlocks(ctx, rs, nil, []Row{{"address": "192.168.1.41", "mac-address": C, "host-name": "galaxy-s24"}})
	devs, _ := st.ListDevices(r.ID)
	if len(devs) != 2 || devs[1].MAC != C || !strings.Contains(devs[1].Origin, A) || len(devs[1].IPs) != 1 || devs[1].IPs[0] != "192.168.1.41" {
		t.Fatalf("host-name match: %+v", devs)
	}
	msgs, _ := st.DueOutbox(nowMs()+1, 20)
	_ = msgs // no chat configured; the event itself is checked below
	evs, _ := st.ListEvents(nil, 30)
	all := ""
	for _, e := range evs {
		all += e.Msg + "\n"
	}
	for _, want := range []string{"nhận IP mới 192.168.1.40", "Nhả chặn IP 192.168.1.21", "xuất hiện với MAC mới " + C} {
		if !strings.Contains(all, want) {
			t.Errorf("missing event %q in:\n%s", want, all)
		}
	}
	// nothing changes when nothing moved
	n := len(bm.Log)
	h.followBlocks(ctx, rs, []Row{{"address": "192.168.1.40", "mac-address": A}}, nil)
	if len(bm.Log) != n {
		t.Fatalf("idle follow must not touch the router: %v", bm.Log[n:])
	}
	// unblocking a device removes all of its IPs, the other device stays blocked
	if err := h.UnblockDevice(ctx, r.ID, A, "admin"); err != nil {
		t.Fatal(err)
	}
	if got := ips(); len(got) != 1 || got[0] != "192.168.1.41" || !bm.on {
		t.Fatalf("after unblocking A: %v", got)
	}
	if err := h.UnblockDevice(ctx, r.ID, C, "admin"); err != nil {
		t.Fatal(err)
	}
	if len(bm.entries) != 0 || bm.on || rs.hasBlocks.Load() {
		t.Fatal("everything must be cleaned up and the function switched off")
	}
}

func TestBlockDeviceNotYetSeen(t *testing.T) {
	bm := &simBindMAC{}
	h, r, _ := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rs := h.get(r.ID)
	if _, err := h.BlockDevice(ctx, r.ID, "62:1B:77:00:00:22", "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if len(bm.entries) != 0 || len(bm.Log) != 0 {
		t.Fatal("no IP known yet: nothing to write")
	}
	h.followBlocks(ctx, rs, []Row{{"address": "192.168.1.77", "mac-address": "62-1b-77-00-00-22"}}, nil)
	if len(bm.entries) != 1 || bm.entries[0].IP != "192.168.1.77" {
		t.Fatalf("device not blocked when it appeared: %+v", bm.entries)
	}
	if _, err := h.BlockDevice(ctx, r.ID, "62:1B:77:00:00:22", "", "", "", "", false, "admin"); err == nil {
		t.Fatal("double block must fail")
	}
	if _, err := h.BlockDevice(ctx, r.ID, "11:22:33:44:55:66", "", "", "", "", true, "admin"); err == nil {
		t.Fatal("host matching without a host name must be refused")
	}
	if err := h.UnblockClient(ctx, r.ID, "192.168.1.77", "admin"); err == nil {
		t.Fatal("a device-owned IP must be unblocked through its device")
	}
}

// Firmware that lists only the entries (nothing at all when empty): blocking
// must still work, verified through the listed entry.
func TestBlockWithEntriesOnlyFirmware(t *testing.T) {
	bm := &simBindMAC{EntriesOnly: true}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := h.BlockDevice(ctx, r.ID, "7E:48:A0:68:B9:52", "192.168.1.216", "realme-16-5G", "realme-16-5G", "", true, "admin"); err != nil {
		t.Fatal(err)
	}
	if !bm.on || len(bm.entries) != 1 || bm.entries[0].IP != "192.168.1.216" {
		t.Fatalf("router state %+v", bm)
	}
	if r2, _ := st.GetRouter(r.ID); !r2.Opts.Block.TurnedOn {
		t.Fatal("TurnedOn must be remembered")
	}
	live, err := h.BlockState(ctx, r.ID, true)
	if err != nil || live.On != nil || len(live.Missing) != 0 {
		t.Fatalf("live %+v %v", live, err)
	}
	if err := h.UnblockDevice(ctx, r.ID, "7E:48:A0:68:B9:52", "admin"); err != nil {
		t.Fatal(err)
	}
	if bm.on || len(bm.entries) != 0 {
		t.Fatal("must be cleaned up and switched off")
	}
}

// Firmware whose "show" prints nothing even with entries: DrayPulse cannot
// verify, so it must undo and report the raw output.
func TestBlockUndoWhenShowIsSilent(t *testing.T) {
	bm := &simBindMAC{Silent: true}
	h, r, st := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := h.BlockDevice(ctx, r.ID, "7E:48:A0:68:B9:52", "192.168.1.216", "", "", "", false, "admin")
	if err == nil || !strings.Contains(err.Error(), "đã hoàn tác") || !strings.Contains(err.Error(), "(rỗng)") {
		t.Fatalf("want undo with raw output, got %v", err)
	}
	if bm.on || len(bm.entries) != 0 {
		t.Fatalf("router must be back as it was: %+v", bm)
	}
	if d, _ := st.ListDevices(r.ID); len(d) != 0 {
		t.Fatal("nothing may be recorded")
	}
}

func TestBindShowUnknownOutput(t *testing.T) {
	if st := parseBindMAC("Show all IP Bind MAC entries.\n"); st.Known || len(st.Entries) != 0 {
		t.Fatalf("%+v", st)
	}
	if !reBindHeader.MatchString("Show all IP Bind MAC entries.\n") || reBindHeader.MatchString("% Unknown command") {
		t.Fatal("header detection")
	}
}

// The exact Vigor 3912S output that made 0.4.1 undo a correct block.
func TestBlockVigor3912SOneLineFormat(t *testing.T) {
	bm := &simBindMAC{OneLine: true}
	h, r, _ := blockHarness(t, bm)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := h.BlockDevice(ctx, r.ID, "6A:FD:1E:76:34:40", "192.168.1.246", "A23-cua-the", "A23-cua-the", "", true, "admin"); err != nil {
		t.Fatal(err)
	}
	if !bm.on || len(bm.entries) != 1 {
		t.Fatalf("%+v", bm)
	}
	if err := h.UnblockDevice(ctx, r.ID, "6A:FD:1E:76:34:40", "admin"); err != nil {
		t.Fatal(err)
	}
	if bm.on || len(bm.entries) != 0 {
		t.Fatal("cleanup")
	}
}

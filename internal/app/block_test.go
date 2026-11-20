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
	if !bm.on || len(bm.entries) != 1 || bm.entries[0].MAC != blockMAC || bm.entries[0].Comment != "DrayPulse" || b.MAC != "F0:2F:74:55:00:21" {
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
	if !strings.Contains(all, "Đã chặn LAPTOP-GD (192.168.1.21) khỏi mạng – bởi admin") || !strings.Contains(all, "Đã bỏ chặn") {
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

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
// DrayOS with a firewall.
func blockHarness(t *testing.T, fw *simFirewall, bc BlockCfg) (*Hub, *Router, *Store) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	sim, err := startSimCLI(ctx, "Vigor", "admin", "pw", func(cmd string) string {
		if out, ok := fw.handle(cmd); ok {
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
		Opts: DrayOpts{SNMPVersion: "off", CLI: "telnet", CLIPort: sim.Port(), Block: bc}}
	r.secret = box.Seal("pw")
	if err := st.SaveRouter(r); err != nil {
		t.Fatal(err)
	}
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); h.Wait(); st.Close() })
	return h, r, st
}

var testBlockCfg = BlockCfg{Enabled: true, Set: 2, Rule: 7, Group: 32, ObjFrom: 181, ObjTo: 183}

func TestBlockUnblockFlow(t *testing.T) {
	fw := newSimFirewall()
	fw.prepareDemoRule(2, 7, "DrayPulse")
	fw.rule(2, 7).enabled = true // left on by mistake: the check must switch it off
	fw.handle("object ip obj 182 -n DP-OLD123")
	h, r, st := blockHarness(t, fw, testBlockCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := h.BlockClient(ctx, r.ID, "F0:2F:74:55:00:21", "", "", "", "admin"); err == nil {
		t.Fatal("blocking must require a passed readiness check")
	}
	chk, err := h.CheckBlocking(ctx, r.ID)
	if err != nil || !chk.OK {
		t.Fatalf("check: %v %+v", err, chk)
	}
	if fw.grps[32].name != "DrayPulse" || fw.rules[[2]int{2, 7}].enabled {
		t.Fatalf("group not prepared or rule still on: %+v %+v", fw.grps[32], fw.rules[[2]int{2, 7}])
	}
	if r2, _ := st.GetRouter(r.ID); !r2.Opts.Block.Ready {
		t.Fatal("ready flag not stored")
	}

	b1, err := h.BlockClient(ctx, r.ID, "f0-2f-74-55-00-21", "192.168.1.21", "LAPTOP-GD", "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if b1.Obj != 181 || fw.objs[181].mac != "F0:2F:74:55:00:21" || fw.objs[181].name != "DP-550021" {
		t.Fatalf("object %+v %+v", b1, fw.objs[181])
	}
	if !fw.rules[[2]int{2, 7}].enabled || !sameMembers(fw.grps[32].members, []int{181}) {
		t.Fatal("rule must be on with one member")
	}
	b2, err := h.BlockClient(ctx, r.ID, "62:1B:77:00:00:22", "", "", "", "admin")
	if err != nil || b2.Obj != 182 { // DP-named leftover object is reusable
		t.Fatalf("%v %+v", err, b2)
	}
	if _, err := h.BlockClient(ctx, r.ID, "62:1B:77:00:00:22", "", "", "", "admin"); err == nil {
		t.Fatal("double block must fail")
	}
	st1, _ := h.BlockState(ctx, r.ID, true)
	if st1.Drift != "" || len(st1.Blocks) != 2 || st1.RuleEnabled == nil || !*st1.RuleEnabled {
		t.Fatalf("state %+v", st1)
	}

	if err := h.UnblockClient(ctx, r.ID, "F0:2F:74:55:00:21", "admin"); err != nil {
		t.Fatal(err)
	}
	if !sameMembers(fw.grps[32].members, []int{182}) || !fw.rules[[2]int{2, 7}].enabled || fw.objs[181].mac != zeroMAC {
		t.Fatalf("after first unblock: %+v rule=%v obj=%+v", fw.grps[32], fw.rules[[2]int{2, 7}].enabled, fw.objs[181])
	}
	// last one: the rule must go off (an empty group is never live)
	if err := h.UnblockClient(ctx, r.ID, "62:1B:77:00:00:22", "admin"); err != nil {
		t.Fatal(err)
	}
	if fw.rules[[2]int{2, 7}].enabled || fw.objs[182].mac != zeroMAC {
		t.Fatal("rule must be off and object blanked after the last unblock")
	}
	evs, _ := st.ListEvents(nil, 20)
	all := ""
	for _, e := range evs {
		all += e.Msg + "\n"
	}
	if !strings.Contains(all, "Đã chặn client LAPTOP-GD (F0:2F:74:55:00:21)") || !strings.Contains(all, "Đã bỏ chặn client") {
		t.Fatalf("events:\n%s", all)
	}
	// nothing outside DrayPulse's own objects, group and rule was touched
	for _, c := range fw.Log {
		ok := strings.Contains(c, "obj 181 ") || strings.Contains(c, "obj 182 ") || strings.Contains(c, "grp 32 ") || strings.Contains(c, "rule 2 7 ")
		if !ok {
			t.Fatalf("touched something else: %q", c)
		}
	}
}

func TestBlockRollsBackWhenMACNotStored(t *testing.T) {
	fw := newSimFirewall()
	fw.prepareDemoRule(2, 7, "DrayPulse")
	h, r, _ := blockHarness(t, fw, testBlockCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if chk, err := h.CheckBlocking(ctx, r.ID); err != nil || !chk.OK {
		t.Fatalf("%v %+v", err, chk)
	}
	fw.RejectMAC = true // firmware ignores MAC objects
	if _, err := h.BlockClient(ctx, r.ID, "F0:2F:74:55:00:21", "", "", "", "admin"); err == nil || !strings.Contains(err.Error(), "không phải") {
		t.Fatalf("want verify error, got %v", err)
	}
	if fw.rules[[2]int{2, 7}].enabled || len(fw.grps[32].members) != 0 {
		t.Fatal("nothing may go live when the MAC was not stored")
	}
}

func TestBlockCheckRefusesUsedSlots(t *testing.T) {
	fw := newSimFirewall()
	fw.handle("object ip grp 32 -n Marketing")
	fw.handle("object ip grp 32 -a 5")
	fw.handle("object ip obj 181 -n Server")
	h, r, _ := blockHarness(t, fw, testBlockCfg) // rule 2/7 still "Pass, source Any"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	chk, err := h.CheckBlocking(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(chk.Problems, "\n")
	if chk.OK || !strings.Contains(all, "IP group 32 đang được dùng") || !strings.Contains(all, "IP object 181 đang được dùng") || !strings.Contains(all, "Block Immediately") {
		t.Fatalf("%+v", chk)
	}
	if fw.grps[32].name != "Marketing" || len(fw.Log) != 3 { // only the 3 setup commands above
		t.Fatalf("check must not change a used group: %+v %v", fw.grps[32], fw.Log)
	}
}

func TestBlockWriteAllowlist(t *testing.T) {
	for _, ok := range []string{"object ip obj 181 -a 4 f0:2f:74:55:00:21", "object ip grp 32 -a 181 182", "ipf rule 2 7 -e 1", "object ip obj 181 -n DP-550021", "ipf rule 2 7 -v"} {
		if !cliWriteCommandAllowed(ok) {
			t.Error("should allow", ok)
		}
		if cliCommandAllowed(ok) && !strings.HasSuffix(ok, "-v") {
			t.Error("read-only list must not contain", ok)
		}
	}
	for _, bad := range []string{"ipf rule 2 7 -F \"1 1\"", "ipf rule 2 7 -s \"g 1 32\"", "object ip obj 181 -a 2", "object ip obj 181 -n Server",
		"object ip grp 32 -n Marketing", "object ip obj 181 -a 4 f0:2f:74:55:00:21; sys reboot", "ipf set -p 1 0", "sys reboot"} {
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

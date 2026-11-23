package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fwHarness runs a hub with one pull router whose CLI is a simulated DrayOS
// with the firewall objects/rules and a Bind IP to MAC table (legacy).
func fwHarness(t *testing.T) (*Hub, *Router, *Store, *simFirewall, *simBindMAC) {
	t.Helper()
	fw, bm := newSimFirewall(), &simBindMAC{}
	h, r, st := blockHarnessWith(t, func(cmd string) string {
		if out, ok := fw.handle(cmd); ok {
			return out
		}
		if out, ok := bm.handle(cmd); ok {
			return out
		}
		return "% Unknown command"
	})
	t.Cleanup(func() {
		for _, c := range fw.Writes() {
			if !fwCommandAllowed(c) {
				t.Errorf("firewall command outside the allowlist: %q", c)
			}
		}
	})
	return h, r, st, fw, bm
}

// blockHarness: a router that only knows Bind IP to MAC.
func blockHarness(t *testing.T, bm *simBindMAC) (*Hub, *Router, *Store) {
	return blockHarnessWith(t, func(cmd string) string {
		if out, ok := bm.handle(cmd); ok {
			return out
		}
		return "% Unknown command"
	})
}

func blockHarnessWith(t *testing.T, handler func(string) string) (*Hub, *Router, *Store) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	sim, err := startSimCLI(ctx, "Vigor", "admin", "pw", handler)
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

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestFwBlockUnblockFlow(t *testing.T) {
	h, r, st, fw, _ := fwHarness(t)
	ctx := testCtx(t)
	for _, bad := range []string{"192.168.1.1", "8.8.8.8", "10.9.9.9", "x"} {
		if _, err := h.BlockClient(ctx, r.ID, bad, "", "", "", "admin"); err == nil {
			t.Fatalf("must refuse %s", bad)
		}
	}
	if len(fw.Writes()) != 0 {
		t.Fatal("refused blocks must not touch the router")
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.21", "", "LAPTOP-GD", "", "admin"); err != nil {
		t.Fatal(err)
	}
	if o := fw.Obj(192); o.name != "DPI192168001021" || o.typ != "single" || o.ip != "192.168.1.21" || o.iface != "Lan" {
		t.Fatalf("object 192 %+v", o)
	}
	if g := fw.Grp(32); g[0] != 192 || g[1] != 0 {
		t.Fatalf("group 32 %v", g)
	}
	if x := fw.Rule(1, 1); !x.on || x.comment != "DrayPulse" || !x.block || x.g1 != 32 || x.g2 != 0 {
		t.Fatalf("rule 1-1 %+v", x)
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.21", "", "", "", "admin"); err == nil {
		t.Fatal("double block must fail")
	}
	const A = "A4:C6:9A:00:00:23"
	if fw.blocked(A) {
		t.Fatal("not blocked yet")
	}
	if _, err := h.BlockDevice(ctx, r.ID, A, "192.168.1.30", "Điện thoại lạ", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if !fw.blocked(A) || fw.blocked("A4:C6:9A:00:00:24") {
		t.Fatal("the device, and only it, must be blocked by MAC")
	}
	if o := fw.Obj(191); o.name != "DP-A4C69A000023" || o.typ != "mac" {
		t.Fatalf("object 191 %+v", o)
	}
	if g := fw.Grp(32); g[0] != 191 || g[1] != 192 {
		t.Fatalf("group 32 %v", g)
	}
	live, err := h.BlockState(ctx, r.ID, true)
	if err != nil || live.On == nil || !*live.On || live.Rule != "1-1" || len(live.Missing) != 0 || len(live.Extra) != 0 {
		t.Fatalf("live %+v %v", live, err)
	}
	if err := h.UnblockClient(ctx, r.ID, "192.168.1.21", "admin"); err != nil {
		t.Fatal(err)
	}
	if o := fw.Obj(192); o.name != "" || o.typ != "mask" || o.ip != "0.0.0.0" {
		t.Fatalf("object 192 must be cleared: %+v", o)
	}
	if g := fw.Grp(32); g[0] != 191 || g[1] != 0 {
		t.Fatalf("group 32 %v", g)
	}
	if err := h.UnblockDevice(ctx, r.ID, A, "admin"); err != nil {
		t.Fatal(err)
	}
	if x := fw.Rule(1, 1); x.on || fw.Grp(32) != [12]int{} || fw.Obj(191).name != "" || fw.blocked(A) {
		t.Fatalf("everything must be removed: rule %+v group %v", x, fw.Grp(32))
	}
	if !fw.DF() {
		t.Fatal("the data filter was on before: it stays on")
	}
	all := eventText(t, st)
	for _, want := range []string{"Đã chặn IP LAPTOP-GD (192.168.1.21) ra Internet – bởi admin", "Đã chặn thiết bị Điện thoại lạ (" + A, "luật Firewall 1-1", "Đã bỏ chặn thiết bị"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing event %q in:\n%s", want, all)
		}
	}
}

// The order that keeps innocent devices safe: the rule is enabled only once
// its group holds the objects; an object leaves the group before it is
// cleared; the rule is off before the last group empties.
func TestFwSafeOrder(t *testing.T) {
	h, r, _, fw, _ := fwHarness(t)
	ctx := testCtx(t)
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:01", "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	w := fw.Writes()
	idx := func(prefix string, from int) int {
		for i := from; i < len(w); i++ {
			if strings.HasPrefix(w[i], prefix) {
				return i
			}
		}
		return -1
	}
	obj, grp, rule := idx("object ip obj 192 -a 4", 0), idx("object ip grp 32 -a", 0), idx("ipf rule 1 1 -e 1", 0)
	if obj < 0 || grp < obj || rule < grp {
		t.Fatalf("object → group → rule, got:\n%s", strings.Join(w, "\n"))
	}
	n := len(w)
	if err := h.UnblockDevice(ctx, r.ID, "3C:52:82:00:00:01", "admin"); err != nil {
		t.Fatal(err)
	}
	w = fw.Writes()
	off, grp, clr := idx("ipf rule 1 1 -e 0", n), idx("object ip grp 32 -a", n), idx("object ip obj 192 -a 0", n)
	if off < 0 || grp < off || clr < grp {
		t.Fatalf("rule off → group → object, got:\n%s", strings.Join(w[n:], "\n"))
	}
}

func TestFwMovesAbovePassRules(t *testing.T) {
	h, r, st, fw, _ := fwHarness(t)
	ctx := testCtx(t)
	fw.SetRule(1, 1, true, "allow-boss", false)
	fw.SetRule(1, 2, true, "xNetBios", true)
	const A = "3C:52:82:00:00:02"
	if _, err := h.BlockDevice(ctx, r.ID, A, "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if x := fw.Rule(1, 1); x.comment != "DrayPulse" || !x.on {
		t.Fatalf("our rule must be first: %+v", x)
	}
	if fw.Rule(1, 2).comment != "allow-boss" || fw.Rule(1, 3).comment != "xNetBios" {
		t.Fatal("the admin's rules keep their order below ours")
	}
	if !fw.blocked(A) {
		t.Fatal("a Pass Immediately rule above must not let the device through")
	}
	if !strings.Contains(eventText(t, st), "đã chuyển luật lên 2 bậc") {
		t.Fatalf("events:\n%s", eventText(t, st))
	}
	// in sync: a comparison writes nothing and says nothing
	rs := h.get(r.ID)
	n, before := len(fw.Writes()), strings.Count(eventText(t, st), "Đối chiếu")
	h.reconcileBlocks(ctx, rs)
	if len(fw.Writes()) != n || strings.Count(eventText(t, st), "Đối chiếu") != before {
		t.Fatalf("in sync must stay quiet: %v", fw.Writes()[n:])
	}
}

func TestFwDataFilterOff(t *testing.T) {
	t.Run("switched on and off by DrayPulse", func(t *testing.T) {
		h, r, st, fw, _ := fwHarness(t)
		ctx := testCtx(t)
		fw.mu.Lock()
		fw.dfOn = false
		fw.mu.Unlock()
		if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:03", "", "", "", "", false, "admin"); err != nil {
			t.Fatal(err)
		}
		if !fw.DF() || !fw.blocked("3C:52:82:00:00:03") {
			t.Fatal("the data filter must be switched on")
		}
		if err := h.UnblockDevice(ctx, r.ID, "3C:52:82:00:00:03", "admin"); err != nil {
			t.Fatal(err)
		}
		if fw.DF() {
			t.Fatal("DrayPulse switched the data filter on, so it switches it off")
		}
		all := eventText(t, st)
		if !strings.Contains(all, "đã bật Data Filter") || !strings.Contains(all, "đã tắt Data Filter") {
			t.Fatalf("events:\n%s", all)
		}
	})
	t.Run("refused with the admin's rules", func(t *testing.T) {
		h, r, st, fw, _ := fwHarness(t)
		ctx := testCtx(t)
		fw.mu.Lock()
		fw.dfOn = false
		fw.mu.Unlock()
		fw.SetRule(1, 1, true, "xNetBios -> DNS", true)
		_, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:04", "", "", "", "", false, "admin")
		var off errFwFilterOff
		if !errors.As(err, &off) || !strings.Contains(err.Error(), "xNetBios -> DNS") {
			t.Fatalf("want errFwFilterOff naming the rule, got %v", err)
		}
		if len(fw.Writes()) != 0 || fw.DF() {
			t.Fatalf("nothing may change: %v", fw.Writes())
		}
		if d, _ := st.ListDevices(r.ID); len(d) != 0 {
			t.Fatal("nothing may be recorded")
		}
	})
}

func TestFwLimit48(t *testing.T) {
	h, r, _, fw, _ := fwHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute) // ~100 changes, each reading every object back
	defer cancel()
	fw.SetRule(1, 1, true, "allow-boss", false) // a "Pass Immediately" rule both must go above
	ip := func(i int) string { return fmt.Sprintf("192.168.1.%d", 100+i) }
	block := func(from, to int) {
		t.Helper()
		for i := from; i < to; i++ {
			if _, err := h.BlockClient(ctx, r.ID, ip(i), "", "", "", "admin"); err != nil {
				t.Fatalf("%d: %v", i, err)
			}
		}
	}
	unblock := func(from, to int) {
		t.Helper()
		for i := from; i < to; i++ {
			if err := h.UnblockClient(ctx, r.ID, ip(i), "admin"); err != nil {
				t.Fatalf("%d: %v", i, err)
			}
		}
	}
	// index of the first write equal to cmd after position from
	at := func(w []string, from int, cmd string) int {
		for i := from; i < len(w); i++ {
			if w[i] == cmd {
				return i
			}
		}
		return -1
	}
	block(0, 24)
	if x := fw.Rule(1, 1); x.comment != "DrayPulse" || x.g1 != 32 || x.g2 != 31 || !x.on {
		t.Fatalf("rule 1 must use groups 32+31: %+v", x)
	}
	if fw.Grp(30) != [12]int{} || fw.Rule(1, 3).comment != "" {
		t.Fatal("the second rule is not needed for 24")
	}
	block(24, 25)
	if x := fw.Rule(1, 2); x.comment != "DrayPulse2" || x.g1 != 30 || x.g2 != 0 || !x.on || !x.block {
		t.Fatalf("25th: second rule %+v", x)
	}
	if fw.Rule(1, 3).comment != "allow-boss" || fw.Rule(1, 1).comment != "DrayPulse" {
		t.Fatalf("both DrayPulse rules above the pass rule: %+v %+v %+v", fw.Rule(1, 1), fw.Rule(1, 2), fw.Rule(1, 3))
	}
	block(25, 48)
	for _, g := range []int{32, 31, 30, 29} {
		if fw.Grp(g)[11] == 0 {
			t.Fatalf("group %d must be full: %v", g, fw.Grp(g))
		}
	}
	if x := fw.Rule(1, 2); x.g1 != 30 || x.g2 != 29 {
		t.Fatalf("rule 2 must use groups 30+29: %+v", x)
	}
	n := len(fw.Writes())
	_, err := h.BlockClient(ctx, r.ID, ip(48), "", "", "", "admin")
	if err == nil || !strings.Contains(err.Error(), "tối đa 48") || len(fw.Writes()) != n {
		t.Fatalf("49th: %v", err)
	}
	// back to 36: group 29 leaves rule 2 before it is emptied
	n = len(fw.Writes())
	unblock(0, 12)
	w := fw.Writes()
	if src, grp := at(w, n, `ipf rule 1 2 -s "g 2 0"`), at(w, n, `object ip grp 29 -a "0 0 0 0 0 0 0 0 0 0 0 0"`); src < 0 || grp < src {
		t.Fatalf("group 29 must leave the rule first (%d, %d)", src, grp)
	}
	// back to 24: rule 2 is switched off before group 30 is emptied
	n = len(fw.Writes())
	unblock(12, 24)
	w = fw.Writes()
	if off, grp := at(w, n, "ipf rule 1 2 -e 0"), at(w, n, `object ip grp 30 -a "0 0 0 0 0 0 0 0 0 0 0 0"`); off < 0 || grp < off {
		t.Fatalf("rule 2 must be off before group 30 is emptied (%d, %d)", off, grp)
	}
	if x := fw.Rule(1, 2); x.on || x.comment != "DrayPulse2" || !fw.Rule(1, 1).on {
		t.Fatalf("rule 2 off, rule 1 on: %+v %+v", fw.Rule(1, 1), x)
	}
	// the 25th again: the disabled rule 2 still names group 29 (empty); it is
	// dropped before the rule is enabled
	fw.handle(`ipf rule 1 2 -s "g 2 29"`)
	n = len(fw.Writes())
	block(0, 1)
	w = fw.Writes()
	if g2, on := at(w, n, `ipf rule 1 2 -s "g 2 0"`), at(w, n, `ipf rule 1 2 -e 1 -D 0 -s "g 1 30" -F "1 0" -m "0 0" -M "DrayPulse2"`); g2 < 0 || on < g2 {
		t.Fatalf("an emptied group must leave the rule before it is enabled (%d, %d)", g2, on)
	}
	if x := fw.Rule(1, 2); !x.on || x.g1 != 30 || x.g2 != 0 {
		t.Fatalf("rule 2 %+v", x)
	}
	// in sync: nothing written
	n = len(fw.Writes())
	h.reconcileBlocks(ctx, h.get(r.ID))
	if len(fw.Writes()) != n {
		t.Fatalf("in sync must write nothing: %v", fw.Writes()[n:])
	}
	// unblock-all switches both rules off
	if _, err := h.UnblockAll(ctx, r.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if fw.Rule(1, 1).on || fw.Rule(1, 2).on || fw.Grp(32) != [12]int{} || fw.Grp(30) != [12]int{} || !fw.Rule(1, 3).on {
		t.Fatalf("after unblock-all: %+v %+v %+v", fw.Rule(1, 1), fw.Rule(1, 2), fw.Rule(1, 3))
	}
}

// Nothing is committed: a reboot loses the block, the comparison puts it back.
func TestFwReconcileAfterReboot(t *testing.T) {
	h, r, st, fw, _ := fwHarness(t)
	ctx := testCtx(t)
	rs := h.get(r.ID)
	fw.Save()
	const A = "3C:52:82:00:00:05"
	if _, err := h.BlockDevice(ctx, r.ID, A, "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.50", "", "", "", "admin"); err != nil {
		t.Fatal(err)
	}
	fw.Reboot()
	if fw.blocked(A) {
		t.Fatal("reboot must lose the block")
	}
	h.reconcileBlocks(ctx, rs)
	if !fw.blocked(A) {
		t.Fatal("the comparison must restore the block")
	}
	rs.mu.RLock()
	dr := rs.drift
	rs.mu.RUnlock()
	if dr == nil || dr.Error != "" || len(dr.Readded) != 2 {
		t.Fatalf("drift %+v", dr)
	}
	if !strings.Contains(eventText(t, st), "Đối chiếu với router: đã tạo lại cấu hình chặn") {
		t.Fatalf("events:\n%s", eventText(t, st))
	}
	// someone switches the rule off in the web UI
	fw.SetRule(1, 1, false, "DrayPulse", true)
	h.reconcileBlocks(ctx, rs)
	if !fw.Rule(1, 1).on || !strings.Contains(eventText(t, st), "đã sửa lại luật chặn") {
		t.Fatalf("rule must be switched on again:\n%s", eventText(t, st))
	}
	n := len(fw.Writes())
	h.reconcileBlocks(ctx, rs)
	if len(fw.Writes()) != n {
		t.Fatalf("in sync must write nothing: %v", fw.Writes()[n:])
	}
}

func TestFwRespectsAdminObjects(t *testing.T) {
	h, r, _, fw, _ := fwHarness(t)
	ctx := testCtx(t)
	fw.handle("object ip obj 192 -n Printer")
	fw.handle("object ip obj 192 -a 1 192.168.1.5")
	fw.handle("object ip grp 31 -n Office")
	fw.handle(`object ip grp 31 -a "192 0 0 0 0 0 0 0 0 0 0 0"`)
	fw.mu.Lock()
	fw.Log = nil
	fw.mu.Unlock()
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:06", "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if fw.Obj(192).name != "Printer" || fw.Obj(191).name != "DP-3C5282000006" {
		t.Fatalf("the admin's object 192 must stay: %+v %+v", fw.Obj(192), fw.Obj(191))
	}
	if fw.Grp(31)[0] != 192 {
		t.Fatal("the admin's group 31 must stay")
	}
	for _, c := range fw.Writes() {
		if strings.Contains(c, "obj 192 ") || strings.Contains(c, "grp 31 ") {
			t.Fatalf("touched the admin's object or group: %q", c)
		}
	}
	// group 31 is needed from the 13th block: refused before any change
	for i := range 11 {
		if _, err := h.BlockClient(ctx, r.ID, fmt.Sprintf("192.168.1.%d", 60+i), "", "", "", "admin"); err != nil {
			t.Fatal(err)
		}
	}
	n := len(fw.Writes())
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.99", "", "", "", "admin"); err == nil || !strings.Contains(err.Error(), "Office") {
		t.Fatalf("want refusal naming group 31, got %v", err)
	}
	if len(fw.Writes()) != n {
		t.Fatalf("a refused block must not write: %v", fw.Writes()[n:])
	}
	if err := h.UnblockClient(ctx, r.ID, "192.168.1.60", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UnblockAll(ctx, r.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if fw.Obj(192).name != "Printer" || fw.Grp(31)[0] != 192 {
		t.Fatal("unblock-all must leave the admin's object and group")
	}
}

// A router that answers OK but does not store the MAC: refused and nothing
// enabled; the half-written object is reused later.
func TestFwRouterIgnoresObject(t *testing.T) {
	h, r, st, fw, _ := fwHarness(t)
	ctx := testCtx(t)
	fw.mu.Lock()
	fw.IgnoreObj = true
	fw.mu.Unlock()
	_, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:07", "", "", "", "", false, "admin")
	if err == nil || !strings.Contains(err.Error(), "router không lưu đối tượng IP 192") {
		t.Fatalf("got %v", err)
	}
	if d, _ := st.ListDevices(r.ID); len(d) != 0 || fw.Rule(1, 1).on {
		t.Fatal("nothing may be recorded or enabled")
	}
	fw.mu.Lock()
	fw.IgnoreObj = false
	fw.mu.Unlock()
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:08", "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if fw.Obj(192).name != "DP-3C5282000008" {
		t.Fatalf("the leftover object must be reused: %+v", fw.Obj(192))
	}
}

func TestFwAllowlist(t *testing.T) {
	for _, ok := range []string{"ipf set -v", "ipf set -d 0", "ipf set -d 1", "ipf rule ?", "ipf rule 1 2 -v", "ipf rule 1 2 -U 0", "ipf rule 1 2 -e 0",
		`ipf rule 1 2 -e 1 -D 0 -s "g 1 32" -F "1 0" -m "0 0" -M "DrayPulse"`, `ipf rule 1 2 -s "g 2 31"`, `ipf rule 1 2 -s "g 2 0"`,
		`ipf rule 1 3 -e 1 -D 0 -s "g 1 30" -F "1 0" -m "0 0" -M "DrayPulse2"`, `ipf rule 1 3 -s "g 2 29"`,
		"object ip grp 30 -v", "object ip grp 29 -n DrayPulse4", `object ip grp 29 -a "150 0 0 0 0 0 0 0 0 0 0 0"`,
		"object ip obj 7 -v", "object ip obj 192 -n DP-A4C69A000023", "object ip obj 150 -n DPI192168001021", `object ip obj 192 -n ""`,
		"object ip obj 192 -i 1", "object ip obj 192 -a 4 a4:c6:9a:00:00:23", "object ip obj 192 -a 1 192.168.1.21", "object ip obj 192 -a 0 0.0.0.0 0.0.0.0",
		"object ip grp 32 -v", "object ip grp 31 -n DrayPulse2", `object ip grp 32 -a "192 191 0 0 0 0 0 0 0 0 0 0"`} {
		if !fwCommandAllowed(ok) {
			t.Error("should allow", ok)
		}
	}
	for _, bad := range []string{"object ip obj 50 -n DP-A4C69A000023", "object ip obj 199 -a 4 a4:c6:9a:00:00:23", "object ip obj 192 -n Printer",
		"object ip obj 192 -a 0 192.168.1.0 255.255.255.0", "object ip grp 28 -v", `object ip grp 28 -a "1 0 0 0 0 0 0 0 0 0 0 0"`, "object ip grp 32 -n Office",
		"object ip grp 30 -n DrayPulse5", `ipf rule 1 2 -e 1 -D 0 -s "g 1 30" -F "1 0" -m "0 0" -M "DrayPulse"`, `ipf rule 1 2 -e 1 -D 0 -s "g 1 32" -F "1 0" -m "0 0" -M "DrayPulse2"`,
		`ipf rule 1 2 -s "g 2 30"`, `ipf rule 1 2 -s "g 1 29"`,
		`ipf rule 1 2 -e 1 -D 0 -s "g 1 32" -F "0 0" -m "0 0" -M "DrayPulse"`, `ipf rule 1 2 -e 1`, `ipf rule 1 2 -M "x"`, "ipf rule 1 2 -U 1",
		"ipf set -d 1; sys reboot", "sys commit", "sys reboot", "ipf flowtrack"} {
		if fwCommandAllowed(bad) {
			t.Error("should refuse", bad)
		}
	}
}

func TestFwParseRealOutput(t *testing.T) {
	// Vigor3912S 4.4.3.2 (trimmed: the interface lists are long)
	rule := "\nFilter Set 1 Rule 2:\n\nStatus  : Enable\nComments: DrayPulse\nIndex(1-15) in Schedule Setup: <null>, <null>, <null>, <null>\n\nClear sessions when schedule is ON: Disable\n\nDirection     : LAN/RT/VPN -> WAN\nSrc Interface : LAN1, LAN2, Routed, VPN,  \nDst Interface : WAN1, WAN2,  \nSource IP     : (g1)IP Group32, \nDestination IP: Any\nService Type  : Any\nFragments     : Don't Care\n\nPass or Block             : Block Immediately\nBranch to Other Filter Set: None\nMac Bind IP               : Non-Strict\n"
	x, ok := parseFwRule(rule)
	if !ok || !x.On || !x.ours() || !x.Block || x.Source != "(g1)IP Group32" {
		t.Fatalf("%+v", x)
	}
	free, _ := parseFwRule("\nFilter Set 1 Rule 4:\n\nStatus  : Disable\nComments: <null>\nSource IP     : Any\nPass or Block             : Pass Immediately\n")
	if !free.free() {
		t.Fatalf("free %+v", free)
	}
	obj, ok := parseFwObj(" IP Object Profile 192\n Name   :[DP-B83BCC324D1D]\n Interface:[Lan]\n Address type:[mac]\n Start ip address:[0.0.0.0]\n End/Mask ip address:[0.0.0.0]\n MAC Address:[B8:3B:CC:32:4D:1D]\n Invert Selection:[0]\n")
	if !ok || !fwObjIs(obj, "mac:B8:3B:CC:32:4D:1D") {
		t.Fatalf("%+v", obj)
	}
	left, _ := parseFwObj(" IP Object Profile 192\n Name   :[DP-B83BCC324D1D]\n Interface:[Any]\n Address type:[mask]\n Start ip address:[0.0.0.0]\n End/Mask ip address:[0.0.0.0]\n MAC Address:[00:00:00:00:00:00]\n")
	if left.empty() || !fwFreeForUs(left) {
		t.Fatalf("a cleared DrayPulse object is free for DrayPulse only: %+v", left)
	}
	if fwFreeForUs(fwObj{Name: "Printer", Type: "mask", IP: "0.0.0.0", MAC: zeroMAC}) {
		t.Fatal("the admin's named object is never free")
	}
	g, ok := parseFwGrp(" IP Group Profile 32\n Name   :[DrayPulse1]\n Interface:[Any]\n Included ip object index:\n [0:][192]\n [1:][0]\n [11:][7]\n")
	if !ok || g.Name != "DrayPulse1" || g.Members[0] != 192 || g.Members[11] != 7 {
		t.Fatalf("%+v", g)
	}
	for in, want := range map[string]string{
		"\nData Filter: Disable\nLog Flag   : Disable\n":                                             "Disable/",
		"\nData Filter: Enable (Start Filter Set = 1)\n":                                             "Enable/1",
		"\nCall Filter: Enable (Start Filter Set = 3)\nData Filter: Enable (Start Filter Set = 2)\n": "Enable/2",
	} {
		m := reFwDF.FindStringSubmatch(in)
		if m == nil || m[1]+"/"+m[2] != want {
			t.Errorf("%q → %v", in, m)
		}
	}
	if m := reFwLimits.FindStringSubmatch("\nUsage:\n\nipf rule s r [-<command> <parameter> | ...\n\ns: set, range 1-12.\nr: rule, range 1-7.\n"); m == nil || m[1] != "12" || m[2] != "7" {
		t.Fatalf("limits %v", m)
	}
}

func TestFwUnblockAllRemovesLegacy(t *testing.T) {
	h, r, st, fw, bm := fwHarness(t)
	ctx := testCtx(t)
	bm.mu.Lock()
	bm.on = true
	bm.entries = []bindEntry{{IP: "192.168.1.40", MAC: blockMAC, Comment: "DrayPulse"}, {IP: "192.168.1.5", MAC: "00:50:7F:22:33:55", Comment: "printer"}}
	bm.mu.Unlock()
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:20", "", "", "Kho-PC-9", "", true, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BlockDevice(ctx, r.ID, "3C:52:82:00:00:21", "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BlockClient(ctx, r.ID, "192.168.1.82", "", "", "", "admin"); err != nil {
		t.Fatal(err)
	}
	st.AddSuggestion(r.ID, Suggestion{MAC: "3C:52:82:00:00:22", RefMAC: "3C:52:82:00:00:20", At: 1})
	n, err := h.UnblockAll(ctx, r.ID, "admin")
	if err != nil || n != 3 {
		t.Fatalf("%d %v", n, err)
	}
	if fw.Rule(1, 1).on || fw.Grp(32) != [12]int{} || fw.blocked("3C:52:82:00:00:20") {
		t.Fatal("firewall pieces must be removed")
	}
	if got := bm.ips(); len(got) != 1 || got[0] != "192.168.1.5" || !bm.on {
		t.Fatalf("only DrayPulse's old entry goes; the admin's and the ON state stay: %v on=%v", got, bm.on)
	}
	d, _ := st.ListDevices(r.ID)
	b, _ := st.ListBlocks(r.ID)
	s, _ := st.ListSuggestions(r.ID, true)
	if len(d)+len(b)+len(s) != 0 || h.get(r.ID).hasBlocks.Load() {
		t.Fatalf("store must be empty: %v %v %v", d, b, s)
	}
	if all := eventText(t, st); !strings.Contains(all, "Đã bỏ chặn TẤT CẢ: 3 thiết bị/IP") || !strings.Contains(all, "xoá 1 mục Bind IP to MAC cũ") {
		t.Fatalf("event:\n%s", all)
	}
	for _, c := range bm.Log {
		if !cliWriteCommandAllowed(c) {
			t.Fatalf("command outside the allowlist: %q", c)
		}
	}
}

// Upgrade from 0.6: a device blocked by Bind IP to MAC moves to the
// firewall at the first comparison; its old entries are removed.
func TestFwMigratesLegacyBlocks(t *testing.T) {
	h, r, st, fw, bm := fwHarness(t)
	ctx := testCtx(t)
	const A = "3C:52:82:00:00:30"
	bm.mu.Lock()
	bm.on = true
	bm.entries = []bindEntry{{IP: "192.168.1.70", MAC: blockMAC, Comment: "DrayPulse"}, {IP: "192.168.1.5", MAC: "00:50:7F:22:33:55", Comment: "printer"}}
	bm.mu.Unlock()
	st.AddDevice(r.ID, Device{MAC: A, ByUser: "admin", At: 1, IPs: []string{"192.168.1.70"}})
	st.AddBlock(r.ID, Block{IP: "192.168.1.70", MAC: A, ByUser: "admin", At: 1})
	st.AddBlock(r.ID, Block{IP: "192.168.1.71", ByUser: "admin", At: 1}) // IP-only: kept, moved to the firewall
	rs := h.get(r.ID)
	h.refreshHasBlocks(rs, r.ID)
	h.reconcileBlocks(ctx, rs)
	if !fw.blocked(A) || fw.Obj(191).ip != "192.168.1.71" && fw.Obj(192).ip != "192.168.1.71" {
		t.Fatalf("device and IP must be on the firewall: %+v %+v", fw.Obj(191), fw.Obj(192))
	}
	if got := bm.ips(); len(got) != 1 || got[0] != "192.168.1.5" {
		t.Fatalf("old DrayPulse entry must go, the admin's stays: %v", got)
	}
	if b, _ := st.ListBlocks(r.ID); len(b) != 1 || b[0].IP != "192.168.1.71" {
		t.Fatalf("store: %+v", b)
	}
	if !strings.Contains(eventText(t, st), "Đã chuyển sang chặn bằng Firewall") {
		t.Fatalf("events:\n%s", eventText(t, st))
	}
	n := len(bm.Log)
	h.reconcileBlocks(ctx, rs)
	if len(bm.Log) != n {
		t.Fatalf("migration runs once: %v", bm.Log[n:])
	}
}

// The incident of v0.5.0: one block cascaded to hundreds of phones sharing a
// factory host name. Host names only suggest, generic ones never match.
func TestHostNameOnlySuggests(t *testing.T) {
	h, r, st, fw, _ := fwHarness(t)
	ctx := testCtx(t)
	rs := h.get(r.ID)
	const A, B, C, D = "7E:48:A0:00:00:01", "7E:48:A0:00:00:02", "7E:48:A0:00:00:03", "7E:48:A0:00:00:04"
	d, err := h.BlockDevice(ctx, r.ID, A, "192.168.1.30", "", "Redmi-12", "", true, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if d.MatchHost || !strings.Contains(eventText(t, st), "tên này phổ biến") {
		t.Fatal("a generic host name must not be followed, and the admin told why")
	}
	var lease []Row
	for i := range 50 {
		lease = append(lease, Row{"address": "192.168.1." + itoaInt(100+i), "mac-address": "02:00:00:00:01:" + hex2(i), "host-name": "Redmi-12"})
	}
	n := len(fw.Writes())
	h.followBlocks(ctx, rs, nil, lease)
	if devs, _ := st.ListDevices(r.ID); len(devs) != 1 || len(fw.Writes()) != n {
		t.Fatalf("50 phones named Redmi-12 must stay untouched: %d devices", len(devs))
	}
	if s, _ := st.ListSuggestions(r.ID, true); len(s) != 0 {
		t.Fatalf("no suggestion for a generic name: %+v", s)
	}
	if _, err := h.BlockDevice(ctx, r.ID, B, "192.168.1.31", "Máy lạ", "Kho-Tablet-2", "", true, "admin"); err != nil {
		t.Fatal(err)
	}
	n = len(fw.Writes())
	same := []Row{{"address": "192.168.1.32", "mac-address": C, "host-name": "kho-tablet-2"}}
	h.followBlocks(ctx, rs, nil, same)
	h.followBlocks(ctx, rs, nil, same)
	if len(fw.Writes()) != n {
		t.Fatalf("a suggestion must not touch the router: %v", fw.Writes()[n:])
	}
	if s, _ := st.ListSuggestions(r.ID, false); len(s) != 1 || s[0].MAC != C {
		t.Fatalf("suggestions %+v", s)
	}
	if c := strings.Count(eventText(t, st), "MAC mới "+C); c != 1 {
		t.Fatalf("want exactly one alert, got %d", c)
	}
	// accepted: blocked by MAC like any other device
	rs.mu.Lock()
	rs.Sections["lease"] = same
	rs.mu.Unlock()
	if _, err := h.AcceptSuggestion(ctx, r.ID, C, "admin"); err != nil {
		t.Fatal(err)
	}
	if !fw.blocked(C) {
		t.Fatal("an accepted suggestion must be blocked")
	}
	// two unblocked MACs with the same name at once: ambiguous, no suggestion
	h.followBlocks(ctx, rs, nil, []Row{{"address": "192.168.1.33", "mac-address": D, "host-name": "Kho-Tablet-2"},
		{"address": "192.168.1.34", "mac-address": "7E:48:A0:00:00:05", "host-name": "Kho-Tablet-2"}})
	if s, _ := st.ListSuggestions(r.ID, false); len(s) != 0 {
		t.Fatalf("ambiguous name must not be suggested: %+v", s)
	}
	if err := h.UnblockDevice(ctx, r.ID, B, "admin"); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedNeverBlocked(t *testing.T) {
	h, r, _, fw, _ := fwHarness(t)
	ctx := testCtx(t)
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
	if len(fw.Writes()) != 0 {
		t.Fatal("nothing may reach the router")
	}
	if _, err := h.BlockDevice(ctx, r.ID, A, "", "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	// the device is added to the protected list later: the comparison lets it go
	setBlockSafety(h, P+", 192.168.1.10, "+A, "", 0)
	h.reconcileBlocks(ctx, rs)
	if fw.blocked(A) || fw.Rule(1, 1).on {
		t.Fatal("a protected device must be released on the router")
	}
}

// Switching blocking off keeps leftovers visible and removable.
func TestUnblockWhenBlockingDisabled(t *testing.T) {
	h, r, st, fw, _ := fwHarness(t)
	ctx := testCtx(t)
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
	if v := h.view(rs, true); v.Blocking == nil || v.Blocking.Enabled || len(v.Blocking.IPs) != 1 || len(v.Blocking.Devices) != 1 || v.Blocking.Max != 48 {
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
	if fw.Rule(1, 1).on || fw.Grp(32) != [12]int{} {
		t.Fatal("everything removed from the router")
	}
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

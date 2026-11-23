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

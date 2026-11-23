package app

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

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

func TestBlockWriteAllowlist(t *testing.T) {
	for _, ok := range []string{"ip bindmac show", "ip bindmac on", "ip bindmac off", "ip bindmac add 192.168.1.21 02:dd:00:00:00:01 DrayPulse", "ip bindmac del 192.168.1.21", "ip arp del 192.168.1.21 LAN"} {
		if !cliWriteCommandAllowed(ok) {
			t.Error("should allow", ok)
		}
		if cliCommandAllowed(ok) {
			t.Error("read-only list must not contain", ok)
		}
	}
	for _, bad := range []string{"ip bindmac del all", "ip bindmac strict_on", "ip bindmac add 192.168.1.21 aa:bb:cc:dd:ee:ff DrayPulse",
		"ip bindmac add 192.168.1.21 02:dd:00:00:00:01 other", "ip bindmac subnet clear", "ip bindmac on; sys reboot", "sys reboot", "ip arp flush", "ip arp del 192.168.1.21 WAN", "ip arp del all LAN", "ip arp add 192.168.1.21 02:dd:00:00:00:01 LAN"} {
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

func TestBindShowUnknownOutput(t *testing.T) {
	if st := parseBindMAC("Show all IP Bind MAC entries.\n"); st.Known || len(st.Entries) != 0 {
		t.Fatalf("%+v", st)
	}
	if !reBindHeader.MatchString("Show all IP Bind MAC entries.\n") || reBindHeader.MatchString("% Unknown command") {
		t.Fatal("header detection")
	}
}

package app

import (
	"bufio"
	"context"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/drayos/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// loadSnmprec reads a LibreNMS/snmpsim .snmprec walk (oid|type|value).
func loadSnmprec(t *testing.T, name string) map[string]gosnmp.SnmpPDU {
	t.Helper()
	f, err := os.Open("testdata/drayos/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m := map[string]gosnmp.SnmpPDU{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), "|", 3)
		if len(p) != 3 {
			continue
		}
		oid, typ, val := p[0], p[1], p[2]
		n, _ := strconv.ParseUint(val, 10, 64)
		switch typ {
		case "2":
			i, _ := strconv.Atoi(val)
			m[oid] = pduInt(i)
		case "4":
			m[oid] = pduStr(val)
		case "4x":
			b, _ := hex.DecodeString(val)
			m[oid] = pduBytes(b)
		case "6":
			m[oid] = pduOID(val)
		case "64":
			m[oid] = pduIP(val)
		case "65":
			m[oid] = pduC32(uint(n))
		case "66":
			m[oid] = pduGauge(uint(n))
		case "67":
			m[oid] = pduTicks(uint32(n))
		case "70":
			m[oid] = pduC64(n)
		}
	}
	return m
}

func TestParseSysVersion(t *testing.T) {
	r := parseSysVersion(fixture(t, "sys_version_2927lac.txt"))
	if r["model"] != "Vigor2927Lac" || r["version"] != "4.5.2.2" || r["name"] != "VP-HaNoi" || r["build"] != "Jul 9 2026 11:31:06" {
		t.Fatalf("%+v", r)
	}
	m, v := parseSysDescr("DrayTek Corporation, Router Model: Vigor2962, Version: 4.3.2.5, Build Date/Time:Sep 28 2023 12:10:20")
	if m != "Vigor2962" || v != "4.3.2.5" {
		t.Fatal(m, v)
	}
}

func TestParseWanStatus(t *testing.T) {
	rows := parseWanStatus(fixture(t, "wan_status_2927.txt"))
	if len(rows) < 8 {
		t.Fatalf("got %d rows", len(rows))
	}
	w1 := rows[0]
	if w1["name"] != "WAN1" || w1["status"] != "up" || w1["mode"] != "DHCP Client" || w1["address"] != "198.51.100.108" ||
		w1["gateway"] != "198.51.100.7" || w1["uptime"] != "17757" || w1["dns"] != "8.8.8.8" {
		t.Fatalf("%+v", w1)
	}
	if rows[1]["status"] != "down" || rows[1]["address"] != "" || rows[2]["name"] != "WAN3" || rows[2]["label"] != "USB_WAN3" || rows[2]["enabled"] != "false" {
		t.Fatalf("%+v %+v", rows[1], rows[2])
	}
}

func TestParseShowStatus(t *testing.T) {
	up, rows := parseShowStatus(fixture(t, "show_status_2927lac.txt"))
	if up != 177*3600+30*60+48 || len(rows) != 6 {
		t.Fatalf("up=%v rows=%d", up, len(rows))
	}
	if rows[0]["status"] != "up" || rows[0]["mode"] != "DHCP Client" || rows[1]["mode"] != "PPPoE" || rows[2]["enabled"] != "false" || rows[4]["line"] != "USB" {
		t.Fatalf("%+v %+v %+v", rows[0], rows[1], rows[2])
	}
	_, old := parseShowStatus(fixture(t, "show_status_2927.txt"))
	if len(old) < 3 || old[0]["status"] != "down" || old[0]["enabled"] != "true" {
		t.Fatalf("%+v", old)
	}
	// IP and GW glued together
	_, glued := parseShowStatus("WAN 1 Status: Connected\nEnable:Yes Line:Ethernet Name:x\nMode:PPPoE Up Time:1:00:00 IP:111.251.202.195GW IP:111.251.202.1\n")
	if glued[0]["address"] != "111.251.202.195" || glued[0]["gateway"] != "111.251.202.1" {
		t.Fatalf("%+v", glued[0])
	}
}

func TestParseARPAndDHCP(t *testing.T) {
	arp := parseARP(fixture(t, "arp_3912.txt"))
	if len(arp) != 3 {
		t.Fatalf("%+v", arp)
	}
	if arp[0]["address"] != "192.168.100.100" || arp[0]["mac-address"] != "AA:BB:CC:DD:EE:FF" || arp[0]["interface"] != "WAN1" {
		t.Fatalf("%+v", arp[0])
	}
	if arp[1]["interface"] != "LAN1" || arp[1]["port"] != "P9" || arp[1]["vlan"] != "VLAN0" || arp[2]["host"] != "HP-Printer" {
		t.Fatalf("%+v %+v", arp[1], arp[2])
	}
	dh := parseDHCP(fixture(t, "dhcp_3912.txt"))
	if len(dh) != 2 || dh[0]["host-name"] != "PC-KHO" || dh[0]["server"] != "LAN1" || dh[1]["mac-address"] != "3C:52:82:11:22:33" {
		t.Fatalf("%+v", dh)
	}
	p, ok := parseRouterPing(fixture(t, "ping_3912.txt"))
	if !ok || p.Sent != 5 || p.Received != 3 || p.RTT != 1 {
		t.Fatalf("%+v", p)
	}
	if _, ok := parseRouterPing("% Unknown command"); ok {
		t.Fatal("unknown command parsed as ping")
	}
}

func TestDraytekSourceSNMP2962(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	walk := loadSnmprec(t, "snmp_vigor2962.snmprec")
	var mu sync.Mutex // the simulated agent reads these from its own goroutine
	ticks := uint32(100000)
	in := uint(4294967000) // close to wrap
	sim, err := startSimSNMP(ctx, "public", func() map[string]gosnmp.SnmpPDU {
		mu.Lock()
		defer mu.Unlock()
		walk[oidSysUpTime] = pduTicks(ticks)
		walk["1.3.6.1.2.1.2.2.1.10.4"] = pduC32(in)
		return walk
	})
	if err != nil {
		t.Fatal(err)
	}
	src := newDraytekSource("127.0.0.1", DrayOpts{SNMPVersion: "2c", SNMPPort: sim.Port()}, SNMPSecrets{Community: "public"}, "", "")
	tctx, c2 := context.WithTimeout(ctx, 15*time.Second)
	defer c2()
	res, err := src.Fetch(tctx, "/system/resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	r := res[0]
	if r["board-name"] != "Vigor2962" || r["version"] != "4.3.2.5" || r["cpu-load"] != "6" || r["mem-load"] != "67" || r["uptime"] != "1000" {
		t.Fatalf("%+v", r)
	}
	if m, ok := memPct(r); !ok || m != 67 {
		t.Fatal("memPct", m, ok)
	}
	ifs, err := src.Fetch(tctx, "/interface", nil)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Row{}
	for _, i := range ifs {
		byName[i["name"]] = i
	}
	if _, ok := byName["V-WAN8"]; ok {
		t.Fatal("disabled virtual WANs should be hidden")
	}
	if _, ok := byName["Loopback"]; ok {
		t.Fatal("loopback should be hidden")
	}
	w1 := byName["WAN1"]
	if w1["type"] != "wan" || w1["running"] != "true" || byName["WAN2"]["disabled"] != "true" || byName["LAN_PORT1"]["type"] != "ether" || byName["LAN"]["type"] != "bridge" {
		t.Fatalf("%+v", byName)
	}
	// 32-bit wrap: counter goes 4294967000 → 1000 ⇒ +1296 bytes
	first, _ := strconv.ParseUint(w1["rx-byte"], 10, 64)
	mu.Lock()
	in, ticks = 1000, 101500
	mu.Unlock()
	ifs, _ = src.Fetch(tctx, "/interface", nil)
	for _, i := range ifs {
		if i["name"] == "WAN1" {
			n, _ := strconv.ParseUint(i["rx-byte"], 10, 64)
			if n-first != 1296 {
				t.Fatalf("wrap: %d → %d", first, n)
			}
		}
	}
	addr, err := src.Fetch(tctx, "/ip/address", nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range addr {
		if a["address"] == "203.0.113.26/32" && a["interface"] == "WAN1" {
			found = true
		}
		if strings.HasPrefix(a["address"], "169.254.") {
			t.Fatal("link-local should be skipped")
		}
	}
	if !found {
		t.Fatalf("%+v", addr)
	}
	wl, _ := src.Fetch(tctx, "/interface/list/member?list=WAN", nil)
	if len(wl) != 1 || wl[0]["interface"] != "WAN1" {
		t.Fatalf("wan list %+v", wl)
	}
	if got := detectWANs(map[string][]Row{"wan_list": wl}); len(got) != 1 || got[0] != "WAN1" {
		t.Fatal(got)
	}
	if _, err := src.Fetch(tctx, "/ip/dhcp-server/lease", nil); err != errNotSupported {
		t.Fatal("leases need CLI", err)
	}
}

func TestCLIAllowlist(t *testing.T) {
	for _, ok := range []string{"sys version", "wan status", "ip arp status", "srv dhcp status", "ip ping 8.8.8.8 WAN1", "show status"} {
		if !cliCommandAllowed(ok) {
			t.Error("should allow", ok)
		}
	}
	for _, bad := range []string{"sys reboot", "sys passwd x", "sys name x", "ip ping 8.8.8.8 WAN1; sys reboot", "ip addr 1.2.3.4", "wan status; sys reboot", "sys versionx", "mngt ftp 1", "sys factory", ""} {
		if cliCommandAllowed(bad) {
			t.Error("should block", bad)
		}
	}
}

func TestCLIClientTelnetSim(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	long := fixture(t, "show_status_2927lac.txt")
	sim, err := startSimCLI(ctx, "Vigor2927", "admin", "s3cret", func(cmd string) string {
		switch cmd {
		case "sys version":
			return fixture(t, "sys_version_2927lac.txt")
		case "show status":
			return strings.ReplaceAll(long, simMore+"\n", "")
		case "ip ping 8.8.8.8 WAN1":
			return fixture(t, "ping_3912.txt")
		}
		return "% Unknown command"
	})
	if err != nil {
		t.Fatal(err)
	}
	c := newCLIClient(CLIConfig{Proto: "telnet", Host: "127.0.0.1", Port: sim.Port(), User: "admin", Pass: "s3cret"})
	defer c.Close()
	tctx, c2 := context.WithTimeout(ctx, 20*time.Second)
	defer c2()
	out, err := c.Run(tctx, "sys version", "show status")
	if err != nil {
		t.Fatal(err)
	}
	if v := parseSysVersion(out["sys version"]); v["model"] != "Vigor2927Lac" {
		t.Fatalf("%q", out["sys version"])
	}
	up, wans := parseShowStatus(out["show status"])
	if up == 0 || len(wans) != 6 || strings.Contains(out["show status"], "MORE") {
		t.Fatalf("paging broken: %d wans\n%s", len(wans), out["show status"])
	}
	// second run reuses the session
	out, err = c.Run(tctx, "ip ping 8.8.8.8 WAN1")
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := parseRouterPing(out["ip ping 8.8.8.8 WAN1"]); !ok || p.Received != 3 {
		t.Fatalf("%q", out)
	}
	if sim.logins.Load() != 1 {
		t.Fatalf("expected session reuse, got %d logins", sim.logins.Load())
	}
	if _, err := c.Run(tctx, "sys reboot"); err == nil {
		t.Fatal("non-allowlisted command must be refused")
	}
	bad := newCLIClient(CLIConfig{Proto: "telnet", Host: "127.0.0.1", Port: sim.Port(), User: "admin", Pass: "wrong"})
	if _, err := bad.Run(tctx, "sys version"); err == nil || !strings.Contains(err.Error(), "sai user") {
		t.Fatalf("want auth error, got %v", err)
	}
}

func TestSyslogParseAndEvents(t *testing.T) {
	m, ok := parseSyslog([]byte("<137>Jan 01 09:00:00 Vigor3900: [H2L][UP][SSLTunnel][@giamdoc]"))
	if !ok || m.Facility != "vpn" || m.Host != "Vigor3900" || m.Severity != 1 {
		t.Fatalf("%+v", m)
	}
	if icon, msg, ok := syslogEvent(m); !ok || icon != "🔐" || msg != "VPN H2L kết nối: giamdoc SSLTunnel" {
		t.Fatal(icon, msg, ok)
	}
	fw, _ := parseSyslog([]byte("<134>Sep 27 16:51:29 DrayTek_TEST: [FILTER][Block][LAN/RT/VPN->WAN, 30:00:19   ][@S:R=2:2, 192.168.188.10:53072->176.34.105.234:8443][TCP][HLen=20, TLen=52, Flag=S, Seq=1, Ack=0, Win=64240]"))
	if fw.Facility != "firewall" {
		t.Fatalf("%+v", fw)
	}
	if _, _, ok := syslogEvent(fw); ok {
		t.Fatal("firewall lines are not events")
	}
	wan, _ := parseSyslog([]byte("<166>Apr 10 16:55:38 Vigor: WAN 1 is down"))
	if _, msg, ok := syslogEvent(wan); !ok || !strings.Contains(msg, "WAN 1 is down") {
		t.Fatal(msg, ok)
	}

	// end to end: UDP packet from the router's IP becomes an event
	dir := t.TempDir()
	st, _ := OpenStore(dir + "/db")
	defer st.Close()
	box, _ := LoadBox(dir + "/key")
	settings, _ := NewSettingsStore(st, box)
	h := NewHub(st, box, settings, false)
	r := &Router{Name: "R", Mode: "pull", Host: "127.0.0.1", Enabled: false, Interval: 60, WANTarget: "8.8.8.8", Opts: DrayOpts{SNMPVersion: "2c"}}
	st.SaveRouter(r)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); h.Wait() }()
	h.Start(ctx)
	if err := h.StartSyslog(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", h.syslog.Addr())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 { // repeats are de-duplicated
		c.Write([]byte("<137>Jan 01 09:00:00 Vigor: [L2L][DOWN][IPsec][@ChiNhanh-HCM]"))
	}
	c.Close()
	waitFor(t, "syslog event", func() bool {
		evs, _ := st.ListEvents(nil, 10)
		return len(evs) == 1 && strings.Contains(evs[0].Msg, "VPN L2L ngắt: ChiNhanh-HCM IPsec")
	})
	rs := h.get(r.ID)
	waitFor(t, "3 syslog lines kept", func() bool {
		rs.mu.RLock()
		defer rs.mu.RUnlock()
		return len(rs.Sections["syslog"]) == 3
	})
	if evs, _ := st.ListEvents(nil, 10); len(evs) != 1 {
		t.Fatalf("repeated syslog lines must give one event: %+v", evs)
	}

	// a sender that is not the router's configured address shows up as unknown…
	r2 := &Router{Name: "HCM", Mode: "pull", Host: "10.99.0.1", Enabled: false, Interval: 60, WANTarget: "8.8.8.8", Opts: DrayOpts{SNMPVersion: "2c"}}
	st.SaveRouter(r2)
	h.Reload(r2.ID)
	c2, _ := net.Dial("udp", h.syslog.Addr()) // comes from 127.0.0.1 = router 1, so use the host name path instead
	c2.Write([]byte("<166>Jan 01 09:00:00 HCM-Vigor: WAN 1 is down"))
	c2.Close()
	waitFor(t, "unknown sender listed", func() bool {
		st1 := h.syslog.Status(r.ID, nil)
		return st1.Received == 4
	})
	// …and is matched by host name once the router's identity is known
	rs2 := h.get(r2.ID)
	rs2.mu.Lock()
	rs2.Identity = "HCM-Vigor"
	rs2.mu.Unlock()
	h.syslog.Invalidate()
	if id, ok := h.syslog.routerFor("10.1.1.1", "hcm-vigor"); !ok || id != r2.ID {
		t.Fatalf("host-name match failed: %v %v", id, ok)
	}
	if _, ok := h.syslog.routerFor("10.1.1.1", "unknown"); ok {
		t.Fatal("unknown host must not match")
	}
	r2.Opts.SyslogFrom = []string{"10.1.1.1"}
	st.SaveRouter(r2)
	h.Reload(r2.ID)
	if id, ok := h.syslog.routerFor("10.1.1.1", ""); !ok || id != r2.ID {
		t.Fatal("extra sender IP must match")
	}
}

func TestParseVlanAndLan(t *testing.T) {
	v := parseVlanStatus(fixture(t, "vlan_status.txt"))
	if len(v) != 5 {
		t.Fatalf("%+v", v)
	}
	if v[0]["vid"] != "10" || v[0]["enabled"] != "true" || v[0]["ports"] != "p1,p2,p3" || v[0]["subnet"] != "LAN1" || v[0]["vlan-on"] != "true" {
		t.Fatalf("vlan0 %+v", v[0])
	}
	if v[1]["ports"] != "p4,s2" || v[1]["pri"] != "2" || v[1]["subnet"] != "LAN2" {
		t.Fatalf("vlan1 %+v", v[1])
	}
	if v[2]["ports"] != "p5,p6" || v[3]["enabled"] != "false" || v[3]["ports"] != "" {
		t.Fatalf("vlan2/3 %+v %+v", v[2], v[3])
	}
	l := parseShowLan(fixture(t, "show_lan.txt"))
	if len(l) != 5 || l[0]["network"] != "192.168.1.0/24" || l[0]["pool-size"] != "200" || l[0]["dhcp"] != "true" {
		t.Fatalf("%+v", l)
	}
	if l[2]["dhcp"] != "false" || l[3]["enabled"] != "false" || l[4]["name"] != "Route" {
		t.Fatalf("%+v %+v", l[2], l[3])
	}
}

func TestParseShowSession(t *testing.T) {
	r := parseShowSession(fixture(t, "show_session.txt"))
	if len(r) != 4 || r[0]["max"] != "60000" || r[0]["current"] != "38810" || r[0]["used"] != "39102" || r[0]["peak"] != "41250" ||
		r[1]["name"] != "WAN1" || r[1]["current"] != "30120" || r[3]["current"] != "0" {
		t.Fatalf("%+v", r)
	}
	if parseShowSession("% Unknown command") != nil {
		t.Fatal("garbage must give nothing")
	}
}

func TestParseFlow(t *testing.T) {
	f, ok := parseFlow("[FILTER][Block][LAN/RT/VPN->WAN, 30:00:19   ][@S:R=2:2, 192.168.188.10:53072->176.34.105.234:8443][TCP][HLen=20, TLen=52, Flag=S, Seq=1, Ack=0, Win=64240]", 5)
	if !ok || f.Src != "192.168.188.10" || f.Dst != "176.34.105.234" || f.DPort != 8443 || f.Proto != "TCP" || f.Action != "block" {
		t.Fatalf("%+v", f)
	}
	f, ok = parseFlow("[FILTER][Pass][LAN/RT/VPN->WAN, 0:00:59 ][@S:R=2:1, 192.168.1.20->8.8.8.8][ICMP][HLen=20, TLen=60]", 6)
	if !ok || f.DPort != 0 || f.Proto != "ICMP" || f.Action != "pass" {
		t.Fatalf("%+v", f)
	}
	if _, ok := parseFlow("WAN 1 is down", 7); ok {
		t.Fatal("not a flow")
	}
	rs := &RState{}
	for i := range 30 {
		rs.addFlow(flowRec{At: int64(i), Src: "192.168.1.20", Dst: "142.250.1.1", DPort: 443, Proto: "TCP", Action: "pass"})
	}
	rs.addFlow(flowRec{At: 99, Src: "192.168.1.20", Dst: "1.2.3.4", DPort: 3389, Proto: "TCP", Action: "block"})
	rs.addFlow(flowRec{At: 100, Src: "192.168.1.21", Dst: "8.8.8.8", DPort: 53, Proto: "UDP", Action: "pass"})
	sum := rs.FlowStats("")
	if sum.Total != 32 || len(sum.Sources) != 2 || sum.Sources[0].IP != "192.168.1.20" || sum.Sources[0].Dests != 2 || sum.Sources[0].Blocked != 1 {
		t.Fatalf("%+v", sum.Sources)
	}
	one := rs.FlowStats("192.168.1.20")
	if len(one.Dests) != 2 || one.Dests[0].Service != "HTTPS" || one.Dests[0].Count != 30 || one.Dests[1].Service != "Remote Desktop" || one.Dests[1].Blocked != 1 {
		t.Fatalf("%+v", one.Dests)
	}
}

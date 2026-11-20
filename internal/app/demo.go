package app

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// The demo router is a simulated Vigor2927 running inside DrayPulse: a small
// SNMP agent and a DrayOS-like Telnet CLI on 127.0.0.1. The normal DrayTek
// reader talks to it, so the demo exercises the real code path.

type demoRouter struct {
	snmp *simSNMP
	cli  *simCLI
	fw   *simFirewall

	mu      sync.Mutex
	started time.Time
	last    time.Time
	bytes   map[int][2]float64 // ifIndex → rx, tx
}

var demoIfs = []struct {
	idx    int
	name   string
	ifType int
	up     bool
	rx, tx float64 // average bit/s
	mac    byte
}{
	{1, "LAN", 6, true, 18e6, 62e6, 0x10},
	{4, "WAN1", 6, true, 55e6, 11e6, 0x11},
	{5, "WAN2", 6, true, 9e6, 3e6, 0x12},
	{6, "WAN3", 6, false, 0, 0, 0x13},
	{27, "LAN_PORT1", 6, true, 6e6, 30e6, 0},
	{28, "LAN_PORT2", 6, true, 4e6, 12e6, 0},
	{29, "LAN_PORT3", 6, true, 2e6, 9e6, 0},
	{30, "LAN_PORT4", 6, true, 3e6, 7e6, 0},
	{31, "LAN_PORT5", 6, true, 5e6, 1e6, 0},
	{32, "LAN_PORT6", 6, false, 0, 0, 0},
	{33, "Loopback", 24, true, 0, 0, 0},
}

// Three networks: office (VLAN 0, LAN1), guest Wi-Fi (VLAN 1, LAN2) and
// cameras (VLAN 2, LAN3).
var demoClients = []struct{ ip, mac, host, port, lan, vlan string }{
	{"192.168.1.10", "00-11-32-AA-10-01", "NAS-Synology", "P1", "LAN1", "VLAN0"},
	{"192.168.1.2", "1C-2A-A3-00-00-02", "SW-Tang1", "P1", "LAN1", "VLAN0"},
	{"192.168.1.3", "1C-2A-A3-00-00-03", "AP-Tang2", "P2", "LAN1", "VLAN0"},
	{"192.168.1.13", "3C-52-82-11-22-33", "HP-LaserJet", "P2", "LAN1", "VLAN0"},
	{"192.168.1.20", "DC-A6-32-00-10-00", "PC-KETOAN", "P3", "LAN1", "VLAN0"},
	{"192.168.1.21", "F0-2F-74-55-00-21", "LAPTOP-GD", "P3", "LAN1", "VLAN0"},
	{"192.168.20.22", "62-1B-77-00-00-22", "iPhone-Lan", "P4", "LAN2", "VLAN1"},
	{"192.168.20.23", "A4-C6-9A-00-00-23", "Galaxy-S24", "P4", "LAN2", "VLAN1"},
	{"10.10.30.11", "BC-32-5F-00-00-11", "", "P5", "LAN3", "VLAN2"},
	{"10.10.30.12", "BC-32-5F-00-00-12", "", "P5", "LAN3", "VLAN2"},
}

func startDemoRouter(ctx context.Context, seed int64) (*demoRouter, error) {
	// boot time fixed per day, so restarting DrayPulse does not look like a router reboot
	boot := time.Now().Truncate(24 * time.Hour).Add(-time.Duration(3+seed)*24*time.Hour - 5*time.Hour)
	d := &demoRouter{started: boot, bytes: map[int][2]float64{}}
	for _, it := range demoIfs { // start near the 32-bit wrap so the 64-bit extension is visible
		d.bytes[it.idx] = [2]float64{4.29e9 - it.rx*5, 4.29e9 - it.tx*7}
	}
	var err error
	d.fw = newSimFirewall()
	d.fw.prepareDemoRule(2, 7, "DrayPulse")
	d.fw.handle("object ip obj 1 -n Server")
	if d.snmp, err = startSimSNMP(ctx, "public", d.snmpData); err != nil {
		return nil, err
	}
	if d.cli, err = startSimCLI(ctx, "VanPhong-HN", "admin", "demo", d.cliReply); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *demoRouter) snmpData() map[string]gosnmp.SnmpPDU {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	dt := 10.0
	if !d.last.IsZero() {
		dt = now.Sub(d.last).Seconds()
	}
	if dt > 0.5 {
		d.last = now
		wave := 0.6 + 0.4*math.Sin(float64(now.Unix())/600)
		for _, it := range demoIfs {
			b := d.bytes[it.idx]
			b[0] += it.rx * wave * (0.8 + 0.4*rand.Float64()) * dt / 8
			b[1] += it.tx * wave * (0.8 + 0.4*rand.Float64()) * dt / 8
			d.bytes[it.idx] = b
		}
	}
	m := map[string]gosnmp.SnmpPDU{
		oidSysDescr:                pduStr("DrayTek Corporation, Router Model: Vigor2927, Version: 4.4.5.2, Build Date/Time:Mar 12 2025 10:21:07"),
		oidSysObjectID:             pduOID("1.3.6.1.4.1.7367"),
		oidSysUpTime:               pduTicks(uint32(now.Sub(d.started).Seconds() * 100)),
		oidSysName:                 pduStr("VanPhong-HN"),
		oidDTModel:                 pduStr("Vigor2927"),
		oidDTFirmware:              pduStr("4.4.5.2 drayos2015_V2927_4452_Release"),
		oidDTBuild:                 pduStr("Mar 12 2025 10:21:07"),
		oidDTMem:                   pduInt(48 + rand.IntN(9)),
		oidDTLanMAC:                pduStr("1449BC000010"),
		oidDTTemp:                  pduStr("No sensor"),
		oidHrCPU + ".0":            pduInt(5 + rand.IntN(20)),
		"1.3.6.1.2.1.25.3.3.1.1.0": pduInt(1),
	}
	for _, it := range demoIfs {
		i := fmt.Sprint(it.idx)
		m["1.3.6.1.2.1.2.2.1.1."+i] = pduInt(it.idx)
		m["1.3.6.1.2.1.2.2.1.2."+i] = pduStr(it.name)
		m["1.3.6.1.2.1.2.2.1.3."+i] = pduInt(it.ifType)
		m["1.3.6.1.2.1.2.2.1.4."+i] = pduInt(1500)
		mac := []byte{}
		if it.mac != 0 {
			mac = []byte{0x14, 0x49, 0xbc, 0, 0, it.mac}
		}
		m["1.3.6.1.2.1.2.2.1.6."+i] = pduBytes(mac)
		m["1.3.6.1.2.1.2.2.1.7."+i] = pduInt(map[bool]int{true: 1, false: 2}[it.up || strings.HasPrefix(it.name, "LAN_PORT")])
		m["1.3.6.1.2.1.2.2.1.8."+i] = pduInt(map[bool]int{true: 1, false: 2}[it.up])
		b := d.bytes[it.idx]
		m["1.3.6.1.2.1.2.2.1.10."+i] = pduC32(uint(uint64(b[0]) & 0xffffffff))
		m["1.3.6.1.2.1.2.2.1.16."+i] = pduC32(uint(uint64(b[1]) & 0xffffffff))
	}
	for _, a := range [][3]string{{"192.168.1.1", "1", "255.255.255.0"}, {"192.168.20.1", "1", "255.255.255.0"}, {"10.10.30.1", "1", "255.255.255.0"},
		{"113.161.20.45", "4", "255.255.255.255"}, {"171.244.8.19", "5", "255.255.255.0"}} {
		m["1.3.6.1.2.1.4.20.1.1."+a[0]] = pduIP(a[0])
		m["1.3.6.1.2.1.4.20.1.2."+a[0]] = pduInt(atoiDef(a[1], 0))
		m["1.3.6.1.2.1.4.20.1.3."+a[0]] = pduIP(a[2])
	}
	// two connected VPNs (DRAYTEK-MIB 7367.2.1.<col>.<row>)
	up := int(now.Sub(d.started).Seconds()) % 86400
	vpn := [][]string{{"ChiNhanh-HCM (lan2lan)", "IPsec IKEv2", "14.161.7.22", "WAN 1", "192.168.10.0/24"},
		{"giamdoc (host2lan)", "SSL Tunnel", "27.72.100.3", "WAN 1", "192.168.1.200/32"}}
	for r, v := range vpn {
		k := fmt.Sprint(r + 1)
		m[oidDTVPN+".1."+k] = pduInt(len(vpn))
		m[oidDTVPN+".2."+k] = pduInt(r + 1)
		m[oidDTVPN+".3."+k] = pduStr(v[0])
		m[oidDTVPN+".4."+k] = pduStr(v[1])
		m[oidDTVPN+".5."+k] = pduIP(v[2])
		m[oidDTVPN+".6."+k] = pduStr(v[3])
		m[oidDTVPN+".7."+k] = pduStr(v[4])
		m[oidDTVPN+".10."+k] = pduInt(20000 + rand.IntN(90000))
		m[oidDTVPN+".11."+k] = pduInt(10000 + rand.IntN(60000))
		m[oidDTVPN+".12."+k] = pduStr(fmt.Sprintf("%02d:%02d:%02d", (up/3600)/(r+1), (up/60)%60, up%60))
	}
	return m
}

func atoiDef(s string, def int) int {
	var n int
	if _, err := fmt.Sscan(s, &n); err != nil {
		return def
	}
	return n
}

// wan2Down: the Viettel line loses Internet for 2 minutes every 15 to show alerts.
func wan2Down() bool { return time.Now().Minute()%15 < 2 }

func (d *demoRouter) cliReply(cmd string) string {
	if out, ok := d.fw.handle(cmd); ok {
		return out
	}
	up := time.Since(d.started)
	clk := func(t time.Duration) string {
		return fmt.Sprintf("%02d:%02d:%02d", int(t.Hours()), int(t.Minutes())%60, int(t.Seconds())%60)
	}
	switch {
	case cmd == "sys version":
		return "Router Model: Vigor2927    Version: 4.4.5.2 English\nProfile version: 4.0.0    Status: 1 (0x48a2c1f0)\n" +
			"Router IP: 192.168.1.1    Netmask: 255.255.255.0\nFirmware Build Date/Time: Mar 12 2025 10:21:07\n" +
			"Router Name: VanPhong-HN\nRevision: 5121_8b1e2 drayos2015_V2927_4452_Release\n"
	case cmd == "wan status":
		return "WAN1: Online, stall=N\n Mode: PPPoE, Up Time=" + clk(up-time.Hour) + "\n IP=113.161.20.45, GW IP=113.161.1.1\n" +
			" TX Packets=81510172, TX Rate(bps)=75456, RX Packets=150271312, RX Rate(bps)=2785960\n Primary DNS=203.162.4.191, Secondary DNS=203.162.4.190\n\n" +
			"WAN2: Online, stall=N\n Mode: DHCP Client, Up Time=" + clk(up/2) + "\n IP=171.244.8.19, GW IP=171.244.8.1\n" +
			" TX Packets=1627523, TX Rate(bps)=25640, RX Packets=2816935, RX Rate(bps)=21944\n Primary DNS=8.8.8.8, Secondary DNS=8.8.4.4\n\n" +
			"WAN3: Offline, stall=N\n Mode: ---, Up Time=00:00:00\n IP=---, GW IP=---\n TX Packets=0, TX Rate(bps)=0, RX Packets=0, RX Rate(bps)=0\n Primary DNS=0.0.0.0, Secondary DNS=0.0.0.0\n\n" +
			"USB_WAN4: Offline, stall=N\n Mode: ---, Up Time=00:00:00\n IP=---, GW IP=---\n TX Packets=0, TX Rate(bps)=0, RX Packets=0, RX Rate(bps)=0\n"
	case cmd == "ip arp status":
		var b strings.Builder
		b.WriteString("[ARP Table]\nIndex IP Address     MAC Address      HOST ID    Interface  VLAN   Port\n")
		b.WriteString("   1   113.161.1.1    00-1E-49-00-01-01             WAN1        ---    --\n")
		for i, c := range demoClients {
			if c.ip == "10.10.30.12" && time.Now().Minute()%20 < 10 {
				continue // a camera that comes and goes
			}
			fmt.Fprintf(&b, "%4d   %-15s%s  %-10s %-10s %-6s %s\n", i+2, c.ip, c.mac, c.host, c.lan, c.vlan, c.port)
		}
		return b.String()
	case cmd == "srv dhcp status":
		var b strings.Builder
		b.WriteString("LAN1       : DHCP Server On    IP Pool: 192.168.1.10 ~ 192.168.1.209\n             Default Gateway: 192.168.1.1\n")
		b.WriteString("LAN2       : DHCP Server On    IP Pool: 192.168.20.10 ~ 192.168.20.59\n             Default Gateway: 192.168.20.1\n")
		b.WriteString(strings.Repeat("-", 72) + "\nIndex   IP Address      MAC Address             Leased Time     HOST ID\n" + strings.Repeat("-", 72) + "\n")
		for _, lan := range []string{"LAN1", "LAN2"} {
			b.WriteString(lan + "\n")
			n := 0
			for i, c := range demoClients[4:] {
				if c.lan != lan {
					continue
				}
				n++
				fmt.Fprintf(&b, "%-8d%-16s%-24s%-16s%s\n", n, c.ip, c.mac, fmt.Sprintf("%02d:%02d:%02d", 20+i, i*7%60, i*13%60), c.host)
			}
		}
		return b.String()
	case cmd == "vlan status":
		return "VLAN is Enable :\n" + strings.Repeat("-", 64) + "\n" +
			"VLAN Enable VID Pri  p1 p2 p3 p4 p5 p6 s1 s2 s3 s4 subnet\n" + strings.Repeat("-", 64) + "\n" +
			"  0    ON    10   0  V  V  V                       1:LAN1\n" +
			"  1    ON    20   2           V           V        2:LAN2\n" +
			"  2    ON    30   0              V  V              3:LAN3\n" +
			"  3    OFF    0   0                                1:LAN1\n" + strings.Repeat("-", 64) + "\n" +
			" Permit untagged device in P1 to access router: ON...."
	case cmd == "show lan":
		return "The LAN settings:\n         ip             mask      dhcp star_ip           pool gateway\n" + strings.Repeat("-", 72) + "\n" +
			"[V]LAN1 192.168.1.1     255.255.255.0 V   192.168.1.10    200 192.168.1.1\n" +
			"[V]LAN2 192.168.20.1    255.255.255.0 V   192.168.20.10   50 192.168.20.1\n" +
			"[V]LAN3 10.10.30.1      255.255.255.0     10.10.30.10     0 10.10.30.1\n" +
			"[X]LAN4 192.168.4.1     255.255.255.0 V   192.168.4.10    100 192.168.4.1\n"
	case cmd == "show status":
		return "System Uptime:" + clk(up) + "\nLAN Status\n"
	case strings.HasPrefix(cmd, "ip ping "):
		f := strings.Fields(cmd)
		time.Sleep(time.Duration(300+rand.IntN(400)) * time.Millisecond)
		if len(f) == 4 && f[3] == "WAN2" && wan2Down() {
			return "Pinging " + f[2] + " with 64 bytes of Data:\nRequest timed out.\nPackets: Sent = 5, Received = 0, Lost = 5 <100% loss>"
		}
		var b strings.Builder
		b.WriteString("Pinging " + f[2] + " with 64 bytes of Data:\n")
		for range 5 {
			fmt.Fprintf(&b, "Receive reply from %s, time=%dms\n", f[2], 8+rand.IntN(25))
		}
		b.WriteString("Packets: Sent = 5, Received = 5, Lost = 0 <0% loss>")
		return b.String()
	}
	return "% Command not found."
}

// demoSource is the real DrayTek reader plus simulated device pings (the
// demo LAN addresses do not exist on this machine).
type demoSource struct{ *draytekSource }

func (d *demoSource) Ping(ctx context.Context, addr, iface string) (PingResult, error) {
	if iface != "" {
		return d.draytekSource.Ping(ctx, addr, iface)
	}
	select {
	case <-ctx.Done():
		return PingResult{}, ctx.Err()
	case <-time.After(time.Duration(50+rand.IntN(200)) * time.Millisecond):
	}
	// .250 is always dead; the printer flaps every ~10 minutes to show alerts.
	if strings.HasSuffix(addr, ".250") || (strings.HasSuffix(addr, ".13") && time.Now().Minute()%10 < 3) {
		return PingResult{Sent: 2, Received: 0, RTT: -1}, nil
	}
	return PingResult{Sent: 2, Received: 2, RTT: 0.4 + rand.Float64()*8}, nil
}

func (h *Hub) demoSource(r *Router) (Source, error) {
	h.demoMu.Lock()
	defer h.demoMu.Unlock()
	if h.demos == nil {
		h.demos = map[int64]*demoRouter{}
	}
	dr := h.demos[r.ID]
	if dr == nil {
		var err error
		if dr, err = startDemoRouter(h.ctx, r.ID); err != nil {
			return nil, err
		}
		h.demos[r.ID] = dr
	}
	src := newDraytekSource("127.0.0.1", DrayOpts{SNMPVersion: "2c", SNMPPort: dr.snmp.Port(), CLI: "telnet", CLIPort: dr.cli.Port(), PingFrom: "local"},
		SNMPSecrets{Community: "public"}, "admin", "demo")
	return &demoSource{src}, nil
}

// seedDemo creates a demo router with a small topology when none exists.
func seedDemo(st *Store) error {
	rs, err := st.ListRouters()
	if err != nil {
		return err
	}
	for _, r := range rs {
		if r.Mode == "demo" {
			return nil
		}
	}
	r := &Router{Name: "Văn phòng Hà Nội (demo)", Mode: "demo", Host: "127.0.0.1", Interval: 10, Enabled: true, WANTarget: "8.8.8.8",
		WANs: []WAN{{Iface: "WAN1", Label: "VNPT"}, {Iface: "WAN2", Label: "Viettel"}},
		Opts: DrayOpts{SNMPVersion: "2c", CLI: "telnet", PingFrom: "local",
			Block: BlockCfg{Enabled: true, Set: 2, Rule: 7, Group: 32, ObjFrom: 181, ObjTo: 192}}}
	if err := st.SaveRouter(r); err != nil {
		return err
	}
	add := func(name, ip, kind string, parent *int64) *int64 {
		m := &Monitor{RouterID: r.ID, Name: name, IP: ip, Kind: kind, ParentID: parent, Enabled: true, Notify: true}
		if err == nil {
			err = st.SaveMonitor(m)
		}
		return &m.ID
	}
	sw := add("Switch tầng 1", "192.168.1.2", "switch", nil)
	add("NAS Synology", "192.168.1.10", "server", sw)
	ap := add("AP tầng 2", "192.168.1.3", "ap", sw)
	add("Máy in HP", "192.168.1.13", "printer", ap)
	cam := add("Switch camera", "", "virtual", sw)
	add("Camera cổng", "10.10.30.11", "camera", cam)
	add("Camera kho", "10.10.30.250", "camera", cam)
	return err
}

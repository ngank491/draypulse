package app

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeDHCPServer answers every DISCOVER with an OFFER from serverIP.
func fakeDHCPServer(t *testing.T, serverIP, offered, gw string) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := buf[:n]
			if n < 240 || req[0] != 1 {
				continue
			}
			resp := make([]byte, 240)
			resp[0], resp[1], resp[2] = 2, 1, 6
			copy(resp[4:8], req[4:8]) // xid
			copy(resp[16:20], net.ParseIP(offered).To4())
			copy(resp[28:34], req[28:34])
			copy(resp[236:], []byte{99, 130, 83, 99})
			resp = append(resp, 53, 1, 2)
			resp = append(resp, 54, 4)
			resp = append(resp, net.ParseIP(serverIP).To4()...)
			resp = append(resp, 3, 4)
			resp = append(resp, net.ParseIP(gw).To4()...)
			resp = append(resp, 255)
			c.WriteToUDP(resp, from)
			// an unrelated packet must be ignored
			bad := append([]byte(nil), resp...)
			binary.BigEndian.PutUint32(bad[4:], 1)
			c.WriteToUDP(bad, from)
		}
	}()
	t.Cleanup(func() { c.Close() })
	return c
}

func TestDHCPProbeFindsServers(t *testing.T) {
	srv := fakeDHCPServer(t, "192.168.1.100", "192.168.1.150", "192.168.1.100")
	cli, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	mac, _ := net.ParseMAC("02:00:00:aa:bb:cc")
	offers, err := probeDHCP(context.Background(), cli, srv.LocalAddr(), mac, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(offers) != 1 || offers[0].Server != "192.168.1.100" || offers[0].Offered != "192.168.1.150" || offers[0].Router != "192.168.1.100" {
		t.Fatalf("%+v", offers)
	}
}

func TestDHCPDiscoverPacket(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:aa:bb:cc")
	p := buildDiscover(0x12345678, mac)
	if p[0] != 1 || binary.BigEndian.Uint32(p[4:]) != 0x12345678 || binary.BigEndian.Uint16(p[10:]) != 0x8000 || net.HardwareAddr(p[28:34]).String() != "02:00:00:aa:bb:cc" {
		t.Fatal("header")
	}
	if p[240] != 53 || p[242] != 1 || p[len(p)-1] != 255 {
		t.Fatal("options")
	}
	if _, ok := parseOffer(p, 0x12345678); ok {
		t.Fatal("a DISCOVER is not an offer")
	}
	if _, ok := parseOffer(p[:100], 0x12345678); ok {
		t.Fatal("short packet")
	}
}

func TestDHCPAlertsForRogueOnly(t *testing.T) {
	h, rs, st := newClientHub(t)
	rs.mu.Lock()
	rs.Sections["lan"] = []Row{{"name": "LAN1", "enabled": "true", "address": "192.168.1.1", "gateway": "192.168.1.1", "network": "192.168.1.0/24"}}
	rs.mu.Unlock()
	allowed := h.dhcpAllowed()
	if allowed["192.168.1.1"] == "" {
		t.Fatalf("router gateway must be allowed: %v", allowed)
	}
	scan := &DHCPScan{Seen: []DHCPSeen{
		{Iface: "eth0", Server: "192.168.1.1", Offered: "192.168.1.50", Allowed: true},
		{Iface: "eth0", Server: "192.168.1.100", Offered: "192.168.1.150", Gateway: "192.168.1.100"},
	}}
	h.dhcpAlerts(scan)
	h.dhcpAlerts(scan) // repeated within 6 h: no second alert
	evs, _ := st.ListEvents(nil, 10)
	n := 0
	for _, e := range evs {
		if e.Level == "warning" && contains(e.Msg, "DHCP server lạ 192.168.1.100") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one alert, got %d: %+v", n, evs)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

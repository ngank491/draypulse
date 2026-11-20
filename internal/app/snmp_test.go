package app

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestSNMPClientAgainstSim(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sim, err := startSimSNMP(ctx, "pub", func() map[string]gosnmp.SnmpPDU {
		m := map[string]gosnmp.SnmpPDU{
			oidSysDescr:  pduStr("DrayTek Vigor Router"),
			oidSysUpTime: pduTicks(123456),
			oidSysName:   pduStr("Vigor2927"),
			// two interfaces
			"1.3.6.1.2.1.2.2.1.2.1":     pduStr("LAN"),
			"1.3.6.1.2.1.2.2.1.2.4":     pduStr("WAN1"),
			"1.3.6.1.2.1.2.2.1.3.1":     pduInt(6),
			"1.3.6.1.2.1.2.2.1.3.4":     pduInt(23),
			"1.3.6.1.2.1.2.2.1.6.1":     pduBytes([]byte{0x00, 0x1d, 0xaa, 1, 2, 3}),
			"1.3.6.1.2.1.2.2.1.7.1":     pduInt(1),
			"1.3.6.1.2.1.2.2.1.7.4":     pduInt(1),
			"1.3.6.1.2.1.2.2.1.8.1":     pduInt(1),
			"1.3.6.1.2.1.2.2.1.8.4":     pduInt(2),
			"1.3.6.1.2.1.2.2.1.10.1":    pduC32(1000),
			"1.3.6.1.2.1.2.2.1.16.1":    pduC32(2000),
			"1.3.6.1.2.1.31.1.1.1.6.1":  pduC64(1 << 40),
			"1.3.6.1.2.1.31.1.1.1.10.1": pduC64(5),
			// address + arp + default route
			"1.3.6.1.2.1.4.20.1.2.192.168.1.1":    pduInt(1),
			"1.3.6.1.2.1.4.20.1.3.192.168.1.1":    pduIP("255.255.255.0"),
			"1.3.6.1.2.1.4.22.1.2.1.192.168.1.50": pduBytes([]byte{0xdc, 0xa6, 0x32, 0, 0, 1}),
			"1.3.6.1.2.1.4.22.1.4.1.192.168.1.50": pduInt(3),
			"1.3.6.1.2.1.4.21.1.7.0.0.0.0":        pduIP("113.161.1.1"),
			"1.3.6.1.2.1.4.21.1.2.0.0.0.0":        pduInt(4),
		}
		for i := 0; i < 120; i++ { // long column to exercise bulk walking
			m["1.3.6.1.4.1.9999.1."+strconv.Itoa(i)] = pduInt(i)
		}
		return m
	})
	if err != nil {
		t.Fatal(err)
	}
	c := newSNMPClient(SNMPConfig{Host: "127.0.0.1", Port: sim.Port(), Community: "pub"})
	tctx, c2 := context.WithTimeout(ctx, 10*time.Second)
	defer c2()
	g, err := c.get(tctx, oidSysDescr, oidSysUpTime, oidSysName, "1.3.6.1.2.1.1.99.0")
	if err != nil {
		t.Fatal(err)
	}
	if g[oidSysName].Str != "Vigor2927" || g[oidSysUpTime].Num != 123456 {
		t.Fatalf("get: %+v", g)
	}
	ifs, err := c.interfaces(tctx)
	if err != nil || len(ifs) != 2 {
		t.Fatalf("ifs %v %+v", err, ifs)
	}
	if ifs[0].Name != "LAN" || ifs[0].RxB != 1<<40 || !ifs[0].HC || ifs[0].MAC != "00:1D:AA:01:02:03" || ifs[1].Oper != 2 || ifs[1].HC {
		t.Fatalf("ifs %+v", ifs)
	}
	big, err := c.walkTable(tctx, map[string]string{"x": "1.3.6.1.4.1.9999.1"})
	if err != nil || len(big) != 120 {
		t.Fatalf("walk %v %d", err, len(big))
	}
	arp, err := c.arpTable(tctx)
	if err != nil || len(arp) != 1 || arp[0]["address"] != "192.168.1.50" || arp[0]["dynamic"] != "true" {
		t.Fatalf("arp %v %+v", err, arp)
	}
	addrs, _ := c.ipAddrs(tctx)
	if len(addrs) != 1 || addrs[0] != [3]string{"192.168.1.1", "1", "255.255.255.0"} {
		t.Fatalf("addrs %+v", addrs)
	}
	rt, _ := c.defaultRoutes(tctx)
	if len(rt) != 1 || rt[0] != [2]string{"113.161.1.1", "4"} {
		t.Fatalf("routes %+v", rt)
	}
	// wrong community → timeout error, quickly
	bad := newSNMPClient(SNMPConfig{Host: "127.0.0.1", Port: sim.Port(), Community: "nope"})
	bctx, c3 := context.WithTimeout(ctx, 3*time.Second)
	defer c3()
	if _, err := bad.get(bctx, oidSysName); err == nil {
		t.Fatal("expected error for wrong community")
	}
}

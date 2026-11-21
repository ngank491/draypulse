package app

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------- Rogue DHCP server detection ----------
//
// A modem or home router plugged into a LAN port hands out wrong addresses
// and gateways; clients then "lose Internet" at random. DrayPulse checks
// every 10 minutes: it broadcasts a DHCPDISCOVER on each of its own network
// interfaces and lists every server that answers with an OFFER. Servers that
// are not one of the monitored routers (or explicitly allowed) raise an
// alert. It only sees the LANs/VLANs the DrayPulse host is attached to, and
// never accepts an offer (no REQUEST is sent, no address is taken).

type dhcpOffer struct {
	Server  string `json:"server"`  // DHCP server identifier (option 54) or sender
	Offered string `json:"offered"` // address it offered
	Router  string `json:"router"`  // gateway it would hand out (option 3)
}

// DHCPSeen is one answering server in the last scan.
type DHCPSeen struct {
	Iface   string `json:"iface"`
	Server  string `json:"server"`
	Offered string `json:"offered"`
	Gateway string `json:"gateway"`
	Allowed bool   `json:"allowed"`
	Owner   string `json:"owner"` // router name that owns the address, if any
}

type DHCPScan struct {
	At     int64      `json:"at"`
	Seen   []DHCPSeen `json:"seen"`
	Errors []string   `json:"errors"`
}

type dhcpWatch struct {
	mu      sync.Mutex
	last    *DHCPScan
	alerted map[string]int64 // server → last alert time
}

// buildDiscover makes a minimal BOOTP/DHCPDISCOVER asking for a broadcast reply.
func buildDiscover(xid uint32, mac net.HardwareAddr) []byte {
	b := make([]byte, 240, 300)
	b[0], b[1], b[2] = 1, 1, 6 // BOOTREQUEST, Ethernet, hlen
	binary.BigEndian.PutUint32(b[4:], xid)
	binary.BigEndian.PutUint16(b[10:], 0x8000) // broadcast flag
	copy(b[28:], mac)
	copy(b[236:], []byte{99, 130, 83, 99}) // magic cookie
	b = append(b, 53, 1, 1)                // DHCPDISCOVER
	b = append(b, 55, 4, 1, 3, 6, 54)      // ask for mask, router, DNS, server id
	b = append(b, 61, 7, 1)                // client identifier
	b = append(b, mac[:6]...)
	return append(b, 255)
}

// parseOffer extracts the server, offered address and gateway from a
// DHCPOFFER answering xid; ok is false for anything else.
func parseOffer(b []byte, xid uint32) (o dhcpOffer, ok bool) {
	if len(b) < 240 || b[0] != 2 || binary.BigEndian.Uint32(b[4:]) != xid || string(b[236:240]) != string([]byte{99, 130, 83, 99}) {
		return o, false
	}
	o.Offered = net.IP(b[16:20]).String()
	msgType := byte(0)
	for i := 240; i < len(b); {
		code := b[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(b) || i+2+int(b[i+1]) > len(b) {
			break
		}
		val := b[i+2 : i+2+int(b[i+1])]
		switch code {
		case 53:
			if len(val) == 1 {
				msgType = val[0]
			}
		case 54:
			if len(val) == 4 {
				o.Server = net.IP(val).String()
			}
		case 3:
			if len(val) >= 4 {
				o.Router = net.IP(val[:4]).String()
			}
		}
		i += 2 + int(b[i+1])
	}
	if msgType != 2 { // DHCPOFFER
		return o, false
	}
	if o.Server == "" {
		o.Server = net.IP(b[20:24]).String() // siaddr as a fallback
	}
	return o, true
}

// probeDHCP sends one DISCOVER on an interface and collects offers.
// send/listen are separate for tests; in production both use port 67/68.
func probeDHCP(ctx context.Context, conn net.PacketConn, dst net.Addr, mac net.HardwareAddr, wait time.Duration) ([]dhcpOffer, error) {
	var xb [4]byte
	rand.Read(xb[:])
	xid := binary.BigEndian.Uint32(xb[:])
	if _, err := conn.WriteTo(buildDiscover(xid, mac), dst); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetReadDeadline(deadline)
	var out []dhcpOffer
	seen := map[string]bool{}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return out, nil
			}
			return out, err
		}
		o, ok := parseOffer(buf[:n], xid)
		if !ok {
			continue
		}
		if o.Server == "0.0.0.0" || o.Server == "" {
			if ua, ok := from.(*net.UDPAddr); ok {
				o.Server = ua.IP.String()
			}
		}
		if !seen[o.Server] {
			seen[o.Server] = true
			out = append(out, o)
		}
	}
}

// dhcpAllowed lists the addresses of the monitored routers (their LAN
// gateways and interface addresses) plus the admin's extra list.
func (h *Hub) dhcpAllowed() map[string]string {
	allowed := map[string]string{}
	for _, rs := range h.all() {
		rs.mu.RLock()
		name := rs.cfg.Name
		for _, l := range rs.Sections["lan"] {
			for _, k := range []string{"gateway", "address"} {
				if l[k] != "" {
					allowed[l[k]] = name
				}
			}
		}
		for _, a := range rs.Sections["address"] {
			if ip := strings.SplitN(a["address"], "/", 2)[0]; ip != "" {
				allowed[ip] = name
			}
		}
		if net.ParseIP(rs.cfg.Host) != nil {
			allowed[rs.cfg.Host] = name
		}
		rs.mu.RUnlock()
	}
	for _, ip := range strings.FieldsFunc(h.settings.Get().DHCPAllowed, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		allowed[ip] = "cho phép trong Cài đặt"
	}
	return allowed
}

// routerForAddr picks the monitored router whose LAN contains ip.
func (h *Hub) routerForAddr(ip string) *RState {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	for _, rs := range h.all() {
		rs.mu.RLock()
		found := false
		for _, l := range rs.Sections["lan"] {
			if p, err := netip.ParsePrefix(l["network"]); err == nil && p.Contains(a) {
				found = true
			}
		}
		for _, x := range rs.Sections["address"] {
			if p, err := netip.ParsePrefix(x["address"]); err == nil && p.Masked().Contains(a) && p.Bits() < 32 {
				found = true
			}
		}
		rs.mu.RUnlock()
		if found {
			return rs
		}
	}
	return nil
}

// ScanDHCP runs one scan over all usable interfaces and raises alerts.
func (h *Hub) ScanDHCP(ctx context.Context) *DHCPScan {
	scan := &DHCPScan{At: nowMs(), Seen: []DHCPSeen{}, Errors: []string{}}
	ifs, err := net.Interfaces()
	if err != nil {
		scan.Errors = append(scan.Errors, err.Error())
		return h.dhcp.store(scan)
	}
	allowed := h.dhcpAllowed()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagBroadcast == 0 || len(ifc.HardwareAddr) != 6 {
			continue
		}
		var mine string
		if addrs, _ := ifc.Addrs(); len(addrs) > 0 {
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
					mine = n.IP.String()
				}
			}
		}
		if mine == "" {
			continue
		}
		conn, err := listenDHCPClient(ifc.Name)
		if err != nil {
			if strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "operation not permitted") {
				err = errors.New("thiếu quyền dùng cổng 68 – chạy DrayPulse bằng dịch vụ cài từ install.sh (đã cấp quyền) hoặc bằng root")
			}
			scan.Errors = append(scan.Errors, fmt.Sprintf("%s: %v", ifc.Name, err))
			continue
		}
		offers, err := probeDHCP(ctx, conn, &net.UDPAddr{IP: net.IPv4bcast, Port: 67}, ifc.HardwareAddr, 4*time.Second)
		conn.Close()
		if err != nil {
			scan.Errors = append(scan.Errors, fmt.Sprintf("%s: %v", ifc.Name, err))
		}
		for _, o := range offers {
			owner, ok := allowed[o.Server]
			scan.Seen = append(scan.Seen, DHCPSeen{Iface: ifc.Name, Server: o.Server, Offered: o.Offered, Gateway: o.Router, Allowed: ok, Owner: owner})
		}
	}
	sort.Slice(scan.Seen, func(i, j int) bool { return !scan.Seen[i].Allowed && scan.Seen[j].Allowed })
	h.dhcpAlerts(scan)
	return h.dhcp.store(scan)
}

func (w *dhcpWatch) store(s *DHCPScan) *DHCPScan {
	w.mu.Lock()
	w.last = s
	w.mu.Unlock()
	return s
}

func (w *dhcpWatch) Last() *DHCPScan {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last
}

// dhcpAlerts notifies once per rogue server every 6 hours.
func (h *Hub) dhcpAlerts(scan *DHCPScan) {
	now := nowMs()
	for _, s := range scan.Seen {
		if s.Allowed {
			continue
		}
		h.dhcp.mu.Lock()
		if h.dhcp.alerted == nil {
			h.dhcp.alerted = map[string]int64{}
		}
		last := h.dhcp.alerted[s.Server]
		fresh := now-last > 6*3600*1000
		if fresh {
			h.dhcp.alerted[s.Server] = now
		}
		h.dhcp.mu.Unlock()
		if !fresh {
			continue
		}
		rs := h.routerForAddr(s.Offered)
		if rs == nil {
			rs = h.routerForAddr(s.Server)
		}
		msg := fmt.Sprintf("Phát hiện DHCP server lạ %s trên mạng (cấp IP %s, gateway %s, qua cổng %s của máy DrayPulse) – có thể là modem/router cắm nhầm vào LAN", s.Server, s.Offered, firstNonEmpty(s.Gateway, "?"), s.Iface)
		if rs == nil {
			log.Print(msg)
			if h.notify != nil {
				h.notify.Alert(Targets{}, "🚨 "+msg)
			}
			continue
		}
		var eff effects
		eff.add(now, "warning", "🚨", msg, true)
		rs.mu.RLock()
		cfg := rs.cfg
		rs.mu.RUnlock()
		h.apply(cfg, eff)
	}
}

// runDHCPWatch scans every 10 minutes while enabled in the settings.
func (h *Hub) runDHCPWatch(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var last time.Time
	for {
		if h.settings.Get().DHCPWatch && time.Since(last) >= 10*time.Minute {
			last = time.Now()
			sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			h.ScanDHCP(sctx)
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

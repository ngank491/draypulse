package app

import (
	"context"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- Syslog receiver: DrayTek pushes VPN/WAN/admin events ----------
//
// Vigor routers send RFC3164-style UDP syslog ("<PRI>Mmm dd hh:mm:ss Name: msg")
// with one facility per category: local0 firewall, local1 VPN, local2 user
// access, local3 call/connection, local4 WAN, local5 router/DSL. Packets are
// matched to routers by source IP. The last lines are kept per router and the
// interesting ones become events.

const syslogKeep = 200

var syslogFacility = map[int]string{16: "firewall", 17: "vpn", 18: "user", 19: "call", 20: "wan", 21: "system"}

var (
	reSyslog    = regexp.MustCompile(`^<(\d{1,3})>(?:1 )?(?:([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+)?(?:([\w.\-]+):?\s+)?(.*)$`)
	reVPNState  = regexp.MustCompile(`\[(H2L|L2L|LAN-LAN|Dial-?in|\w+)\]\s*\[(UP|DOWN)\]\s*(?:\[([^\]]*)\])?\s*(?:\[@?([^\]]*)\])?`)
	reWANEvent  = regexp.MustCompile(`(?i)\bWAN\s*\d+\b.*\b(up|down|connected|disconnected|online|offline)\b|PPP(oE)?\b.*\b(closed|up|down|fail)`)
	reAdminAuth = regexp.MustCompile(`(?i)(admin|management|web ?ui|telnet|ssh)\b.*\b(login|logged|log in|fail|failed|denied|blocked)`)
)

type syslogMsg struct {
	Facility string
	Severity int
	Host     string
	Text     string
}

func parseSyslog(b []byte) (syslogMsg, bool) {
	s := strings.TrimRight(string(b), "\r\n\x00")
	m := reSyslog.FindStringSubmatch(s)
	if m == nil {
		return syslogMsg{}, false
	}
	pri, _ := strconv.Atoi(m[1])
	text := strings.TrimSpace(m[4])
	if len(text) > 400 {
		text = truncateUTF8(text, 400)
	}
	fac := syslogFacility[pri/8]
	if fac == "" {
		fac = "other"
	}
	return syslogMsg{Facility: fac, Severity: pri % 8, Host: m[3], Text: text}, true
}

// syslogEvent decides whether a line becomes an event (icon, message).
func syslogEvent(m syslogMsg) (icon, msg string, ok bool) {
	switch m.Facility {
	case "vpn":
		if v := reVPNState.FindStringSubmatch(m.Text); v != nil {
			who := strings.TrimSpace(strings.Trim(v[4]+" "+v[3], " "))
			if v[2] == "UP" {
				return "🔐", "VPN " + v[1] + " kết nối: " + who, true
			}
			return "🔓", "VPN " + v[1] + " ngắt: " + who, true
		}
	case "wan", "system":
		if reWANEvent.MatchString(m.Text) {
			return "🌐", "Syslog: " + m.Text, true
		}
	}
	if m.Facility != "firewall" && reAdminAuth.MatchString(m.Text) {
		return "🔑", "Syslog: " + m.Text, true
	}
	return "", "", false
}

type syslogServer struct {
	h    *Hub
	conn net.PacketConn

	mu       sync.Mutex
	byIP     map[string]int64 // source IP → router id
	at       time.Time
	lastMsg  map[int64]map[string]int64 // de-duplication per router
	perMin   map[int64]int
	minute   int64
	Unknown  int
	LastFrom string
}

// StartSyslog listens on addr (e.g. ":5514"). It stops with ctx.
func (h *Hub) StartSyslog(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	s := &syslogServer{h: h, conn: pc, lastMsg: map[int64]map[string]int64{}, perMin: map[int64]int{}}
	h.syslog = s
	go func() { <-ctx.Done(); pc.Close() }()
	go s.serve()
	log.Printf("nhận syslog từ router tại UDP %s", pc.LocalAddr())
	return nil
}

func (s *syslogServer) Addr() string { return s.conn.LocalAddr().String() }

// routerFor maps a source address to a router by its configured host.
func (s *syslogServer) routerFor(ip string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byIP == nil || time.Since(s.at) > time.Minute {
		s.byIP, s.at = map[string]int64{}, time.Now()
		for _, rs := range s.h.all() {
			rs.mu.RLock()
			host, id, mode := rs.cfg.Host, rs.cfg.ID, rs.cfg.Mode
			rs.mu.RUnlock()
			if host == "" || mode == "demo" {
				continue
			}
			if net.ParseIP(host) != nil {
				s.byIP[host] = id
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			addrs, _ := net.DefaultResolver.LookupHost(ctx, host)
			cancel()
			for _, a := range addrs {
				s.byIP[a] = id
			}
		}
	}
	id, ok := s.byIP[ip]
	return id, ok
}

func (s *syslogServer) serve() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		ip := addr.String()
		if ua, ok := addr.(*net.UDPAddr); ok {
			ip = ua.IP.String()
		}
		m, ok := parseSyslog(buf[:n])
		if !ok {
			continue
		}
		id, ok := s.routerFor(ip)
		if !ok {
			s.mu.Lock()
			s.Unknown++
			s.LastFrom = ip
			s.mu.Unlock()
			continue
		}
		s.h.observeSyslog(id, m, nowMs(), s)
	}
}

// allow rate-limits events (30/min per router) and drops repeats within 60 s.
func (s *syslogServer) allow(id int64, msg string, now int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if min := now / 60000; min != s.minute {
		s.minute, s.perMin = min, map[int64]int{}
	}
	seen := s.lastMsg[id]
	if seen == nil {
		seen = map[string]int64{}
		s.lastMsg[id] = seen
	}
	if t, ok := seen[msg]; ok && now-t < 60000 {
		return false
	}
	if len(seen) > 500 {
		clear(seen)
	}
	seen[msg] = now
	s.perMin[id]++
	return s.perMin[id] <= 30
}

func (h *Hub) observeSyslog(id int64, m syslogMsg, now int64, s *syslogServer) {
	rs := h.get(id)
	if rs == nil {
		return
	}
	var eff effects
	rs.mu.Lock()
	if m.Facility != "firewall" || m.Severity <= 4 { // firewall logs are too chatty to keep
		row := Row{"time": strconv.FormatInt(now, 10), "facility": m.Facility, "severity": strconv.Itoa(m.Severity), "message": m.Text}
		lines := append(rs.Sections["syslog"], row)
		if len(lines) > syslogKeep {
			lines = lines[len(lines)-syslogKeep:]
		}
		rs.Sections["syslog"], rs.SectionAt["syslog"] = lines, now
	}
	icon, msg, ok := syslogEvent(m)
	if ok && s.allow(id, msg, now) {
		eff.add(now, "info", icon, msg, false)
	}
	h.finish(rs, &eff, now)
	cfg := rs.cfg
	rs.mu.Unlock()
	h.apply(cfg, eff)
}

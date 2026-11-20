package app

import (
	"context"
	"errors"
	"log"
	"net"
	"regexp"
	"sort"
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

const syslogKeep = 300

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

// srcStat counts packets from one sender address.
type srcStat struct {
	IP     string `json:"ip"`
	Count  int    `json:"count"`
	LastAt int64  `json:"lastAt"`
	Host   string `json:"host"`   // name in the syslog header
	Sample string `json:"sample"` // last message
}

type syslogServer struct {
	h     *Hub
	conns []net.PacketConn
	Addrs []string // addresses actually listening
	Fails []string // addresses that could not be opened, with the reason

	mu      sync.Mutex
	byIP    map[string]int64 // source IP → router id
	byName  map[string]int64 // syslog host name → router id (only when unique)
	at      time.Time
	lastMsg map[int64]map[string]int64 // de-duplication per router
	perMin  map[int64]int
	minute  int64
	recv    map[int64]*srcStat // per router
	unknown map[string]*srcStat
}

// StartSyslog listens on a comma-separated list of UDP addresses
// (e.g. ":514,:5514"). Addresses that cannot be opened are reported but do
// not stop the others; it fails only when none opens.
func (h *Hub) StartSyslog(ctx context.Context, addrs string) error {
	s := &syslogServer{h: h, lastMsg: map[int64]map[string]int64{}, perMin: map[int64]int{},
		recv: map[int64]*srcStat{}, unknown: map[string]*srcStat{}}
	for _, a := range strings.Split(addrs, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			s.Fails = append(s.Fails, a+": "+err.Error())
			log.Printf("không mở được cổng syslog %s: %v", a, err)
			continue
		}
		s.conns = append(s.conns, pc)
		s.Addrs = append(s.Addrs, pc.LocalAddr().String())
		log.Printf("nhận syslog từ router tại UDP %s", pc.LocalAddr())
	}
	h.syslog = s
	if len(s.conns) == 0 {
		return errors.New("không mở được cổng syslog nào")
	}
	for _, pc := range s.conns {
		go func() { <-ctx.Done(); pc.Close() }()
		go s.serve(pc)
	}
	return nil
}

func (s *syslogServer) Addr() string {
	if len(s.Addrs) == 0 {
		return ""
	}
	return s.Addrs[0]
}

// Invalidate forgets the address map after routers change.
func (s *syslogServer) Invalidate() {
	s.mu.Lock()
	s.byIP = nil
	s.mu.Unlock()
}

// routerFor maps a packet to a router: by the router's host address, by the
// extra sender IPs configured for it, or by its name in the syslog header.
func (s *syslogServer) routerFor(ip, host string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byIP == nil || time.Since(s.at) > time.Minute {
		s.byIP, s.byName, s.at = map[string]int64{}, map[string]int64{}, time.Now()
		names := map[string][]int64{}
		for _, rs := range s.h.all() {
			rs.mu.RLock()
			cfg, ident := rs.cfg, rs.Identity
			rs.mu.RUnlock()
			for _, extra := range cfg.Opts.SyslogFrom {
				s.byIP[extra] = cfg.ID
			}
			if ident != "" {
				names[strings.ToLower(ident)] = append(names[strings.ToLower(ident)], cfg.ID)
			}
			if cfg.Host == "" || cfg.Mode == "demo" { // the demo's 127.0.0.1 is not a real sender
				continue
			}
			if net.ParseIP(cfg.Host) != nil {
				s.byIP[cfg.Host] = cfg.ID
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			addrs, _ := net.DefaultResolver.LookupHost(ctx, cfg.Host)
			cancel()
			for _, a := range addrs {
				s.byIP[a] = cfg.ID
			}
		}
		for n, ids := range names {
			if len(ids) == 1 && n != "draytek" && n != "vigor" {
				s.byName[n] = ids[0]
			}
		}
	}
	if id, ok := s.byIP[ip]; ok {
		return id, true
	}
	id, ok := s.byName[strings.ToLower(host)]
	return id, ok
}

func (s *syslogServer) serve(pc net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := pc.ReadFrom(buf)
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
		now := nowMs()
		id, ok := s.routerFor(ip, m.Host)
		s.mu.Lock()
		if !ok {
			u := s.unknown[ip]
			if u == nil {
				if len(s.unknown) >= 20 {
					s.mu.Unlock()
					continue
				}
				u = &srcStat{IP: ip}
				s.unknown[ip] = u
			}
			u.Count, u.LastAt, u.Host, u.Sample = u.Count+1, now, m.Host, truncateUTF8(m.Text, 160)
			s.mu.Unlock()
			continue
		}
		r := s.recv[id]
		if r == nil {
			r = &srcStat{}
			s.recv[id] = r
		}
		r.IP, r.Count, r.LastAt, r.Host = ip, r.Count+1, now, m.Host
		delete(s.unknown, ip)
		s.mu.Unlock()
		s.h.observeSyslog(id, m, now, s)
	}
}

// SyslogStatus is what the Syslog tab shows to diagnose missing logs.
type SyslogStatus struct {
	Listening []string  `json:"listening"`
	Failed    []string  `json:"failed"`
	Received  int       `json:"received"`
	LastAt    int64     `json:"lastAt"`
	LastFrom  string    `json:"lastFrom"`
	Unknown   []srcStat `json:"unknown"`
	Extra     []string  `json:"extra"` // extra sender IPs configured for this router
}

func (s *syslogServer) Status(routerID int64, extra []string) SyslogStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := SyslogStatus{Listening: append([]string{}, s.Addrs...), Failed: append([]string{}, s.Fails...), Unknown: []srcStat{}, Extra: extra}
	if st.Extra == nil {
		st.Extra = []string{}
	}
	if r := s.recv[routerID]; r != nil {
		st.Received, st.LastAt, st.LastFrom = r.Count, r.LastAt, r.IP
	}
	for _, u := range s.unknown {
		st.Unknown = append(st.Unknown, *u)
	}
	sort.Slice(st.Unknown, func(i, j int) bool { return st.Unknown[i].LastAt > st.Unknown[j].LastAt })
	return st
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
	row := Row{"time": strconv.FormatInt(now, 10), "facility": m.Facility, "severity": strconv.Itoa(m.Severity), "message": m.Text}
	lines := append(rs.Sections["syslog"], row)
	if len(lines) > syslogKeep {
		lines = lines[len(lines)-syslogKeep:]
	}
	rs.Sections["syslog"], rs.SectionAt["syslog"] = lines, now
	icon, msg, ok := syslogEvent(m)
	if ok && s.allow(id, msg, now) {
		eff.add(now, "info", icon, msg, false)
	}
	h.finish(rs, &eff, now)
	cfg := rs.cfg
	rs.mu.Unlock()
	h.apply(cfg, eff)
}

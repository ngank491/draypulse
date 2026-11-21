package app

import (
	"regexp"
	"sort"
	"strconv"
)

// ---------- "What is this device accessing?" from DrayTek firewall syslog ----------
//
// With firewall logging on, every matched connection produces a line like
//
//	[FILTER][Block][LAN/RT/VPN->WAN, 30:00:19 ][@S:R=2:2, 192.168.188.10:53072->176.34.105.234:8443][TCP][HLen=20, …]
//
// DrayPulse keeps the last connections per router in memory and summarises
// them per LAN device (sources) and per destination.

const flowKeep = 20000

type flowRec struct {
	At     int64
	Src    string
	Dst    string
	DPort  int
	Proto  string
	Action string // pass | block
}

var (
	reFlowAction = regexp.MustCompile(`\[(Pass|Block)\]`)
	reFlowAddr   = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{1,5}))?\s*->\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{1,5}))?`)
	reFlowProto  = regexp.MustCompile(`\[(TCP|UDP|ICMP|IGMP|GRE|ESP)\]`)
)

// parseFlow extracts one connection from a firewall syslog line.
func parseFlow(text string, at int64) (flowRec, bool) {
	m := reFlowAddr.FindStringSubmatch(text)
	if m == nil {
		return flowRec{}, false
	}
	f := flowRec{At: at, Src: m[1], Dst: m[3], Action: "pass"}
	f.DPort, _ = strconv.Atoi(m[4])
	if a := reFlowAction.FindStringSubmatch(text); a != nil && a[1] == "Block" {
		f.Action = "block"
	}
	if p := reFlowProto.FindStringSubmatch(text); p != nil {
		f.Proto = p[1]
	}
	return f, true
}

// addFlow appends to the router's ring (rs.mu held).
func (rs *RState) addFlow(f flowRec) {
	rs.flows = append(rs.flows, f)
	if len(rs.flows) > flowKeep {
		rs.flows = append([]flowRec(nil), rs.flows[len(rs.flows)-flowKeep:]...)
	}
}

type FlowSource struct {
	IP      string `json:"ip"`
	Flows   int    `json:"flows"`
	Dests   int    `json:"dests"`
	Blocked int    `json:"blocked"`
	Last    int64  `json:"last"`
}

type FlowDest struct {
	Dst     string `json:"dst"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"`
	Last    int64  `json:"last"`
}

type FlowSummary struct {
	Total   int          `json:"total"`
	Since   int64        `json:"since"`
	Sources []FlowSource `json:"sources"`
	Dests   []FlowDest   `json:"dests"` // for one source (src set), else overall
}

var wellKnownPorts = map[int]string{20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3",
	123: "NTP", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP", 853: "DNS-over-TLS", 993: "IMAPS", 995: "POP3S", 1194: "OpenVPN",
	1723: "PPTP", 1935: "RTMP (livestream)", 3389: "Remote Desktop", 3478: "STUN (gọi video)", 5060: "SIP", 5222: "XMPP/chat", 5223: "Apple push",
	5228: "Google push", 8080: "HTTP-alt", 8443: "HTTPS-alt", 8883: "MQTT", 19302: "STUN (Google Meet)", 51820: "WireGuard"}

// FlowStats summarises the router's recent firewall connections; with src
// set, the destinations of that one device.
func (rs *RState) FlowStats(src string) FlowSummary {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	sum := FlowSummary{Total: len(rs.flows), Sources: []FlowSource{}, Dests: []FlowDest{}}
	if len(rs.flows) > 0 {
		sum.Since = rs.flows[0].At
	}
	srcs := map[string]*FlowSource{}
	srcDests := map[string]map[string]bool{}
	dests := map[string]*FlowDest{}
	for _, f := range rs.flows {
		s := srcs[f.Src]
		if s == nil {
			s = &FlowSource{IP: f.Src}
			srcs[f.Src], srcDests[f.Src] = s, map[string]bool{}
		}
		s.Flows++
		s.Last = max(s.Last, f.At)
		srcDests[f.Src][f.Dst] = true
		if f.Action == "block" {
			s.Blocked++
		}
		if src != "" && f.Src != src {
			continue
		}
		k := f.Dst + "|" + strconv.Itoa(f.DPort) + "|" + f.Proto
		d := dests[k]
		if d == nil {
			d = &FlowDest{Dst: f.Dst, Port: f.DPort, Proto: f.Proto, Service: wellKnownPorts[f.DPort]}
			dests[k] = d
		}
		d.Count++
		d.Last = max(d.Last, f.At)
		if f.Action == "block" {
			d.Blocked++
		}
	}
	for ip, s := range srcs {
		s.Dests = len(srcDests[ip])
		sum.Sources = append(sum.Sources, *s)
	}
	for _, d := range dests {
		sum.Dests = append(sum.Dests, *d)
	}
	sort.Slice(sum.Sources, func(i, j int) bool { return sum.Sources[i].Flows > sum.Sources[j].Flows })
	sort.Slice(sum.Dests, func(i, j int) bool { return sum.Dests[i].Count > sum.Dests[j].Count })
	if len(sum.Sources) > 100 {
		sum.Sources = sum.Sources[:100]
	}
	if len(sum.Dests) > 200 {
		sum.Dests = sum.Dests[:200]
	}
	return sum
}

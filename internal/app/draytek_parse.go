package app

import (
	"regexp"
	"strconv"
	"strings"
)

// Parsers for DrayOS (3.x/4.x) CLI output. Formats follow real captures from
// Vigor 2927/2962/3912 (see docs/DRAYTEK-NGUON.md). Columns sometimes run
// together, so everything is matched with regexes instead of fixed widths.

var (
	reVerModel   = regexp.MustCompile(`Router Model:\s*(\S+)\s+Version:\s*([\w.]+)`)
	reVerName    = regexp.MustCompile(`(?m)^\s*Router Name:\s*(.*?)\s*$`)
	reVerBuild   = regexp.MustCompile(`(?m)Firmware Build Date/Time:\s*(.*?)\s*$`)
	reVerRev     = regexp.MustCompile(`(?m)^\s*Revision:\s*(.*?)\s*$`)
	reSysDescr   = regexp.MustCompile(`Router Model:\s*([\w ]+?),\s*Version:\s*([\w.]+)`)
	reWanNum     = regexp.MustCompile(`(?i)WAN\s*(\d+)`)
	reUptimeClk  = regexp.MustCompile(`(\d+):(\d{1,2}):(\d{1,2})`)
	reShowUptime = regexp.MustCompile(`System Uptime:\s*([\d:]+)`)
)

// parseSysVersion reads "sys version".
func parseSysVersion(s string) Row {
	r := Row{}
	if m := reVerModel.FindStringSubmatch(s); m != nil {
		r["model"], r["version"] = m[1], m[2]
	}
	if m := reVerName.FindStringSubmatch(s); m != nil {
		r["name"] = m[1]
	}
	if m := reVerBuild.FindStringSubmatch(s); m != nil {
		r["build"] = strings.Join(strings.Fields(m[1]), " ")
	}
	if m := reVerRev.FindStringSubmatch(s); m != nil {
		r["revision"] = m[1]
	}
	return r
}

// parseSysDescr reads the SNMP sysDescr of DrayOS:
// "DrayTek Corporation, Router Model: Vigor2962, Version: 4.3.2.5, Build Date/Time:Sep 28 2023 12:10:20".
func parseSysDescr(s string) (model, version string) {
	if m := reSysDescr.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1]), m[2]
	}
	return "", ""
}

// normWAN maps "WAN 1", "WAN1", "USB_WAN3", "PVC_WAN5" to the SNMP name "WAN1".
func normWAN(s string) string {
	if m := reWanNum.FindStringSubmatch(s); m != nil {
		return "WAN" + m[1]
	}
	return strings.TrimSpace(s)
}

// clockSeconds parses "177:30:48" (hours may exceed 24).
func clockSeconds(s string) float64 {
	m := reUptimeClk.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	h, _ := strconv.Atoi(m[1])
	mi, _ := strconv.Atoi(m[2])
	se, _ := strconv.Atoi(m[3])
	return float64(h*3600 + mi*60 + se)
}

func dashEmpty(s string) string {
	s = strings.TrimSpace(s)
	if s == "---" || s == "--" || s == "-" || s == "0.0.0.0" {
		return ""
	}
	return s
}

var (
	reWanHead  = regexp.MustCompile(`(?m)^\s*(\w*WAN\d+)\s*:\s*(\w+)(?:,\s*stall=(\w))?`)
	reWanMode  = regexp.MustCompile(`Mode:\s*([^,\n]*?),\s*Up Time=([\d:]+)`)
	reWanIP    = regexp.MustCompile(`IP=([\d.]+|---)`)
	reWanGW    = regexp.MustCompile(`GW IP=([\d.]+|---)`)
	reWanDNS   = regexp.MustCompile(`Primary DNS=([\d.]+)`)
	reShowHead = regexp.MustCompile(`(?m)^\s*WAN\s*(\d+)\s+Status:\s*(\w+)`)
	reShowEn   = regexp.MustCompile(`Enable:\s*(\w+)`)
	reShowLine = regexp.MustCompile(`Line:\s*(\S+)`)
	reShowMode = regexp.MustCompile(`Mode:\s*(.*?)\s+Up Time:\s*([\d:]+)`)
	reShowIP   = regexp.MustCompile(`\bIP:\s*([\d.]+|---)`)
	reShowGW   = regexp.MustCompile(`GW IP:\s*([\d.]+|---)`)
)

// splitBlocks cuts text at each header match.
func splitBlocks(s string, head *regexp.Regexp) [][2]string {
	idx := head.FindAllStringSubmatchIndex(s, -1)
	var out [][2]string
	for i, loc := range idx {
		end := len(s)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		out = append(out, [2]string{s[loc[0]:loc[1]], s[loc[1]:end]})
	}
	return out
}

// parseWanStatus reads "wan status". Rows: name, label, status (up|down),
// mode, uptime (s), address, gateway, dns.
func parseWanStatus(s string) []Row {
	var out []Row
	for _, b := range splitBlocks(s, reWanHead) {
		h := reWanHead.FindStringSubmatch(b[0])
		r := Row{"name": normWAN(h[1]), "label": h[1], "state": h[2], "status": "down", "enabled": "true"}
		if strings.EqualFold(h[2], "Online") || strings.EqualFold(h[2], "Connected") {
			r["status"] = "up"
		}
		if m := reWanMode.FindStringSubmatch(b[1]); m != nil {
			r["mode"] = dashEmpty(m[1])
			r["uptime"] = strconv.FormatFloat(clockSeconds(m[2]), 'f', 0, 64)
			if r["mode"] == "" {
				r["enabled"] = "false"
			}
		}
		if m := reWanGW.FindStringSubmatch(b[1]); m != nil {
			r["gateway"] = dashEmpty(m[1])
		}
		if m := reWanIP.FindStringSubmatch(strings.Replace(b[1], "GW IP=", "GW=", 1)); m != nil {
			r["address"] = dashEmpty(m[1])
		}
		if m := reWanDNS.FindStringSubmatch(b[1]); m != nil {
			r["dns"] = dashEmpty(m[1])
		}
		out = append(out, r)
	}
	return out
}

// parseShowStatus reads "show status" (older/alternative WAN summary).
func parseShowStatus(s string) (uptime float64, wans []Row) {
	if m := reShowUptime.FindStringSubmatch(s); m != nil {
		uptime = clockSeconds(m[1])
	}
	for _, b := range splitBlocks(s, reShowHead) {
		h := reShowHead.FindStringSubmatch(b[0])
		r := Row{"name": "WAN" + h[1], "label": "WAN" + h[1], "state": h[2], "status": "down", "enabled": "true"}
		if strings.EqualFold(h[2], "Connected") || strings.EqualFold(h[2], "Online") {
			r["status"] = "up"
		}
		if m := reShowEn.FindStringSubmatch(b[1]); m != nil && !strings.EqualFold(m[1], "Yes") {
			r["enabled"] = "false"
		}
		if m := reShowLine.FindStringSubmatch(b[1]); m != nil {
			r["line"] = m[1]
		}
		if m := reShowMode.FindStringSubmatch(b[1]); m != nil {
			r["mode"] = dashEmpty(m[1])
			r["uptime"] = strconv.FormatFloat(clockSeconds(m[2]), 'f', 0, 64)
		}
		if m := reShowGW.FindStringSubmatch(b[1]); m != nil {
			r["gateway"] = dashEmpty(m[1])
		}
		// IP and "GW IP" can run together ("IP:1.2.3.4GW IP:..."): drop the GW part first
		if m := reShowIP.FindStringSubmatch(strings.Replace(b[1], "GW IP:", " GW:", 1)); m != nil {
			r["address"] = dashEmpty(m[1])
		}
		wans = append(wans, r)
	}
	return uptime, wans
}

var (
	reMACPat  = `[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5}`
	reARPLine = regexp.MustCompile(`^\s*\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*(` + reMACPat + `)\s*(.*?)\s*$`)
	reDHCPRow = regexp.MustCompile(`^\s*\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(` + reMACPat + `)\s+(\S+)\s*(.*?)\s*>?\s*$`)
	reDHCPLAN = regexp.MustCompile(`^\s*((?:LAN|DMZ|IP_ROUTED)\S*)\s*(?::|$)`)
	reIfaceNm = regexp.MustCompile(`^(?i)(LAN|WAN|DMZ|VPN|IP_?ROUTED|USB|PVC|SFP|WLAN|SSID)\S*$`)
)

func dashMAC(m string) string { return normMAC(strings.ReplaceAll(m, "-", ":")) }

// parseARP reads "ip arp status":
//
//	Index IP Address     MAC Address      HOST ID    Interface  VLAN   Port
//	   2   192.168.1.10   08-00-27-5D-1A-09           LAN1       VLAN0   P9
func parseARP(s string) []Row {
	var out []Row
	for _, line := range strings.Split(s, "\n") {
		m := reARPLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		r := Row{"address": m[1], "mac-address": dashMAC(m[2]), "status": "reachable", "dynamic": "true"}
		f := strings.Fields(m[3])
		// find the interface column; host id (optional) is before it, VLAN and port after
		for i, x := range f {
			if reIfaceNm.MatchString(x) {
				r["interface"] = x
				if i > 0 {
					r["host"] = strings.Join(f[:i], " ")
				}
				if i+1 < len(f) {
					r["vlan"] = dashEmpty(f[i+1])
				}
				if i+2 < len(f) {
					r["port"] = dashEmpty(f[i+2])
				}
				break
			}
		}
		if r["mac-address"] == "" || r["mac-address"] == "00:00:00:00:00:00" {
			continue
		}
		out = append(out, r)
	}
	return out
}

// parseDHCP reads "srv dhcp status": leases grouped under a LAN header line.
func parseDHCP(s string) []Row {
	var out []Row
	lan := ""
	for _, line := range strings.Split(s, "\n") {
		if m := reDHCPLAN.FindStringSubmatch(line); m != nil && !strings.Contains(line, "Index") {
			lan = m[1]
		}
		m := reDHCPRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		host := strings.TrimSpace(strings.TrimSuffix(m[4], ">"))
		out = append(out, Row{"address": m[1], "active-address": m[1], "mac-address": dashMAC(m[2]),
			"expires-after": m[3], "host-name": host, "server": lan, "status": "bound", "dynamic": "true"})
	}
	return out
}

var (
	rePingSum   = regexp.MustCompile(`Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+)`)
	rePingReply = regexp.MustCompile(`(?i)reply from [^,]+,\s*time[=<]\s*(\d+(?:\.\d+)?)\s*ms`)
)

// parseRouterPing reads "ip ping": replies with times plus a summary line.
func parseRouterPing(s string) (PingResult, bool) {
	res := PingResult{RTT: -1}
	var sum float64
	n := 0
	for _, m := range rePingReply.FindAllStringSubmatch(s, -1) {
		v, _ := strconv.ParseFloat(m[1], 64)
		sum += v
		n++
	}
	if m := rePingSum.FindStringSubmatch(s); m != nil {
		res.Sent, _ = strconv.Atoi(m[1])
		res.Received, _ = strconv.Atoi(m[2])
	} else if n > 0 {
		res.Sent, res.Received = n, n
	} else if !strings.Contains(strings.ToLower(s), "ping") {
		return res, false // not ping output at all (unknown command?)
	} else {
		res.Sent = 1
	}
	if n > 0 {
		res.RTT = sum / float64(n)
	}
	return res, true
}

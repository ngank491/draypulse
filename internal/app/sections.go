package app

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Row is one item read from a router with every value normalised to a string.
// Field names are the same whatever the transport (SNMP, CLI or demo).
type Row map[string]string

type PingResult struct {
	Sent     int
	Received int
	RTT      float64 // milliseconds, -1 when unknown
}

// Source is anything that can read a router: the DrayTek reader or the demo.
type Source interface {
	Fetch(ctx context.Context, path string, props []string) ([]Row, error)
	Ping(ctx context.Context, addr, iface string) (PingResult, error)
}

var errNotSupported = errors.New("router không có mục này")

// section describes one read-only table we keep from the router. Paths are
// logical names answered by the DrayTek reader (see draytek.go).
type section struct {
	Name  string
	Path  string
	Props []string
}

var ifaceProps = []string{"name", "type", "running", "disabled", "comment", "mac-address", "rx-byte", "tx-byte", "actual-mtu", "speed"}

var resourceProps = []string{"uptime", "version", "board-name", "architecture-name", "cpu-load", "mem-load", "build", "sys-descr"}

var wanStatusProps = []string{"name", "label", "state", "status", "enabled", "mode", "line", "uptime", "address", "gateway", "dns"}

var vpnProps = []string{"name", "service", "caller-id", "address", "uptime", "interface", "tx-rate", "rx-rate"}

var sections = []section{
	{"address", "/ip/address", []string{"address", "network", "interface", "disabled", "dynamic", "invalid", "comment"}},
	{"lease", "/ip/dhcp-server/lease", []string{"address", "active-address", "mac-address", "host-name", "server", "status", "expires-after", "dynamic"}},
	{"arp", "/ip/arp", []string{"address", "mac-address", "interface", "status", "dynamic", "invalid", "host", "vlan", "port"}},
	{"bridge_host", "/interface/bridge/host", []string{"mac-address", "on-interface", "bridge", "local", "dynamic"}},
	{"route", "/ip/route?dst-address=0.0.0.0/0", []string{"dst-address", "gateway", "immediate-gw", "distance", "active", "disabled", "dynamic", "comment"}},
	{"ppp_active", "/ppp/active", vpnProps},
	{"wan_list", "/interface/list/member?list=WAN", []string{"list", "interface", "disabled"}},
	{"wan_status", "/draytek/wan", wanStatusProps},
	{"vlan", "/draytek/vlan", vlanProps},
	{"lan", "/draytek/lan", lanProps},
	{"session", "/draytek/session", []string{"name", "max", "current", "used", "peak"}},
	{"health", "/system/health", []string{"name", "value", "type"}},
	{"identity", "/system/identity", []string{"name"}},
}

func sectionByName(name string) *section {
	for i := range sections {
		if sections[i].Name == name {
			return &sections[i]
		}
	}
	return nil
}

const maxSectionRows = 5000

// cleanRows keeps only the allowed fields; protects against oversized pushes
// and ensures secrets (e.g. PPP passwords) can never be stored.
func cleanRows(rows []Row, props []string) []Row {
	if len(rows) > maxSectionRows {
		rows = rows[:maxSectionRows]
	}
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		c := Row{}
		for _, p := range props {
			if v, ok := r[p]; ok {
				if len(v) > 256 {
					v = v[:256]
				}
				c[p] = v
			}
		}
		out = append(out, c)
	}
	return out
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

var durPart = regexp.MustCompile(`(\d+(?:\.\d+)?)(ms|us|w|d|h|m|s)`)
var clockPart = regexp.MustCompile(`(\d+):(\d+):(\d+(?:\.\d+)?)`)

// rosSeconds parses durations: "1w2d3h4m5s", "2d03:04:05", "10ms", "1ms500us".
func rosSeconds(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	total := 0.0
	if m := clockPart.FindStringSubmatch(s); m != nil {
		h, _ := strconv.ParseFloat(m[1], 64)
		mi, _ := strconv.ParseFloat(m[2], 64)
		se, _ := strconv.ParseFloat(m[3], 64)
		total += h*3600 + mi*60 + se
		s = strings.Replace(s, m[0], "", 1)
	}
	for _, m := range durPart.FindAllStringSubmatch(s, -1) {
		n, _ := strconv.ParseFloat(m[1], 64)
		total += n * map[string]float64{"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001, "us": 0.000001}[m[2]]
	}
	return total
}

func truthy(v string) bool { return v == "true" || v == "yes" }

func parseUint(v string) (uint64, bool) {
	n, err := strconv.ParseUint(v, 10, 64)
	return n, err == nil
}

func parseFloat(v string) (float64, bool) {
	f, err := strconv.ParseFloat(v, 64)
	return f, err == nil
}

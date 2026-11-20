package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- DrayTek Vigor source: SNMP for metrics, optional CLI for tables ----------
//
// The hub asks for logical paths ("/system/resource", "/interface", ...) and
// gets rows with the same field names whatever the transport. This file maps
// DrayOS data onto those rows:
//
//	SNMP  sysDescr/sysUpTime/sysName, DRAYTEK-MIB (7367.3.x model, firmware,
//	      memory %), HOST-RESOURCES hrProcessorLoad.0 (CPU %), IF-MIB ifTable
//	      (32-bit counters, extended to 64-bit here), ipAddrTable, default
//	      route, VPN sessions (7367.2.1)
//	CLI   sys version, wan status / show status, ip arp status,
//	      srv dhcp status, ip ping <target> WANx   (all read-only)

// DrayTek enterprise OIDs (DRAYTEK-MIB, verified on Vigor 2927/2962 walks).
const (
	oidDTModel    = "1.3.6.1.4.1.7367.3.1.0"
	oidDTFirmware = "1.3.6.1.4.1.7367.3.2.0"
	oidDTBuild    = "1.3.6.1.4.1.7367.3.3.0"
	oidDTMem      = "1.3.6.1.4.1.7367.3.7.0"
	oidDTLanMAC   = "1.3.6.1.4.1.7367.3.8.0"
	oidDTTemp     = "1.3.6.1.4.1.7367.1.1.0"
	oidHrCPU      = "1.3.6.1.2.1.25.3.3.1.2" // hrProcessorLoad, DrayOS uses index .0
	oidDTVPN      = "1.3.6.1.4.1.7367.2.1"   // all connected VPNs
)

// DrayOpts holds the DrayTek-specific connection settings of a router.
type DrayOpts struct {
	SNMPVersion string   `json:"snmpVersion"` // "2c" | "1" | "3" | "off"
	SNMPPort    int      `json:"snmpPort"`
	SNMPUser    string   `json:"snmpUser,omitempty"`
	AuthProto   string   `json:"authProto,omitempty"`
	PrivProto   string   `json:"privProto,omitempty"`
	CLI         string   `json:"cli"` // "" (off) | "telnet" | "ssh"
	CLIPort     int      `json:"cliPort"`
	PingFrom    string   `json:"pingFrom"` // "local" (DrayPulse host, default) | "router"
	Block       BlockCfg `json:"block"`
}

// BlockCfg reserves router resources for MAC blocking: a firewall rule the
// admin built once in the web UI (source = IP group, action = Block), the IP
// group, and a range of IP object indexes DrayPulse may use.
type BlockCfg struct {
	Enabled bool `json:"enabled"`
	Set     int  `json:"set"`     // filter set 1-12
	Rule    int  `json:"rule"`    // rule 1-7
	Group   int  `json:"group"`   // IP group 1-32
	ObjFrom int  `json:"objFrom"` // IP object range, 1-192
	ObjTo   int  `json:"objTo"`
	Ready   bool `json:"ready"` // set by the readiness check, cleared when the slots change
}

// SNMPSecrets are stored encrypted, separately from the options.
type SNMPSecrets struct {
	Community string `json:"community,omitempty"`
	AuthPass  string `json:"authPass,omitempty"`
	PrivPass  string `json:"privPass,omitempty"`
}

type draytekSource struct {
	host string
	snmp *snmpClient // nil when SNMP is off
	cli  *cliClient  // nil when CLI is off
	opts DrayOpts

	mu       sync.Mutex
	counters map[string]*ctr64 // 32-bit counter → 64-bit extension per interface
	lastUp   float64
	cliAt    time.Time
	cliOut   map[string]string
	cliErr   error
	ifNames  map[string]string // ifIndex → name, refreshed with every interface read
	model    string
	access   Row // how DrayPulse connects (for the audit; no secrets)
}

type ctr64 struct {
	last [2]uint64
	acc  [2]uint64
}

func newDraytekSource(host string, o DrayOpts, sec SNMPSecrets, cliUser, cliPass string) *draytekSource {
	d := &draytekSource{host: host, opts: o, counters: map[string]*ctr64{}, ifNames: map[string]string{}}
	d.access = Row{"snmp-version": o.SNMPVersion, "cli": o.CLI}
	if o.CLI != "" {
		d.access["cli-port"] = strconv.Itoa(newCLIClient(CLIConfig{Proto: o.CLI, Port: o.CLIPort}).cfg.Port)
	}
	switch o.SNMPVersion {
	case "1", "2c", "":
		c := strings.ToLower(sec.Community)
		d.access["snmp-community-default"] = strconv.FormatBool(c == "public" || c == "private" || c == "draytek")
	case "3":
		d.access["snmp-v3-level"] = map[bool]string{true: "noAuthNoPriv"}[sec.AuthPass == ""]
		if sec.AuthPass != "" {
			d.access["snmp-v3-level"] = map[bool]string{true: "authPriv", false: "authNoPriv"}[sec.PrivPass != ""]
		}
	}
	if o.SNMPVersion != "off" {
		d.snmp = newSNMPClient(SNMPConfig{Host: host, Port: o.SNMPPort, Version: o.SNMPVersion, Community: sec.Community,
			User: o.SNMPUser, AuthProto: o.AuthProto, AuthPass: sec.AuthPass, PrivProto: o.PrivProto, PrivPass: sec.PrivPass})
	}
	if o.CLI == "telnet" || o.CLI == "ssh" {
		d.cli = newCLIClient(CLIConfig{Proto: o.CLI, Host: host, Port: o.CLIPort, User: cliUser, Pass: cliPass})
	}
	return d
}

// Close releases the kept CLI session.
func (d *draytekSource) Close() {
	if d.cli != nil {
		d.cli.Close()
	}
}

var errNeedCLI = errors.New("cần bật Telnet/SSH để đọc mục này")

// slow-cycle CLI commands, read together in one session and cached briefly
var drayCLICmds = []string{"sys version", "wan status", "ip arp status", "srv dhcp status", "vlan status", "show lan"}

func (d *draytekSource) cliData(ctx context.Context) (map[string]string, error) {
	if d.cli == nil {
		return nil, errNeedCLI
	}
	d.mu.Lock()
	if time.Since(d.cliAt) < 30*time.Second {
		out, err := d.cliOut, d.cliErr
		d.mu.Unlock()
		return out, err
	}
	d.mu.Unlock()
	out, err := d.cli.Run(ctx, drayCLICmds...)
	if err == nil {
		if ws := out["wan status"]; len(parseWanStatus(ws)) == 0 {
			// some builds lack "wan status": fall back to "show status"
			if o, e := d.cli.Run(ctx, "show status"); e == nil {
				out["show status"] = o["show status"]
			}
		}
	}
	d.mu.Lock()
	d.cliAt, d.cliOut, d.cliErr = time.Now(), out, err
	d.mu.Unlock()
	return out, err
}

func (d *draytekSource) cliWANs(ctx context.Context) ([]Row, error) {
	out, err := d.cliData(ctx)
	if err != nil {
		return nil, err
	}
	if rows := parseWanStatus(out["wan status"]); len(rows) > 0 {
		return rows, nil
	}
	_, rows := parseShowStatus(out["show status"])
	return rows, nil
}

func (d *draytekSource) Fetch(ctx context.Context, path string, _ []string) ([]Row, error) {
	switch strings.SplitN(path, "?", 2)[0] {
	case "/system/resource":
		r, err := d.resource(ctx)
		if err != nil {
			return nil, err
		}
		return []Row{r}, nil
	case "/interface":
		return d.interfaces(ctx)
	case "/system/identity":
		return d.identity(ctx)
	case "/ip/address":
		return d.addresses(ctx)
	case "/ip/arp":
		return d.arp(ctx)
	case "/interface/bridge/host":
		return d.bridgeHosts(ctx)
	case "/ip/dhcp-server/lease":
		out, err := d.cliData(ctx)
		if err != nil {
			return nil, errNotSupported
		}
		return parseDHCP(out["srv dhcp status"]), nil
	case "/ip/route":
		return d.routes(ctx)
	case "/interface/list/member":
		return d.wanList(ctx)
	case "/ppp/active":
		return d.vpns(ctx)
	case "/draytek/wan":
		rows, err := d.cliWANs(ctx)
		if err != nil {
			return nil, errNotSupported
		}
		return rows, nil
	case "/draytek/vlan":
		out, err := d.cliData(ctx)
		if err != nil {
			return nil, errNotSupported
		}
		return parseVlanStatus(out["vlan status"]), nil
	case "/draytek/lan":
		out, err := d.cliData(ctx)
		if err != nil {
			return nil, errNotSupported
		}
		return parseShowLan(out["show lan"]), nil
	case "/system/health":
		return d.health(ctx)
	case "/draytek/access":
		return []Row{d.access}, nil
	}
	if cmd, ok := strings.CutPrefix(path, "/draytek/cli/"); ok {
		if d.cli == nil {
			return nil, errNotSupported
		}
		out, err := d.cli.Run(ctx, cmd)
		if err != nil {
			return nil, err
		}
		var rows []Row
		for _, l := range strings.Split(out[cmd], "\n") {
			if strings.TrimSpace(l) != "" {
				rows = append(rows, Row{"line": strings.TrimRight(l, " ")})
			}
		}
		return rows, nil
	}
	return nil, errNotSupported
}

// ---------- resource / identity ----------

func (d *draytekSource) resource(ctx context.Context) (Row, error) {
	r := Row{"architecture-name": "DrayOS"}
	if d.snmp == nil {
		return d.resourceCLI(ctx, r)
	}
	g, err := d.snmp.get(ctx, oidSysDescr, oidSysUpTime, oidSysName, oidDTModel, oidDTFirmware, oidDTBuild, oidDTMem)
	if err != nil {
		return nil, err
	}
	if len(g) == 0 {
		return nil, errors.New("router trả lời SNMP nhưng không có dữ liệu (kiểm tra quyền xem của community/user)")
	}
	up := float64(g[oidSysUpTime].Num) / 100
	r["uptime"] = strconv.FormatFloat(up, 'f', 0, 64)
	model, ver := parseSysDescr(g[oidSysDescr].Str)
	if v := strings.TrimSpace(g[oidDTModel].Str); v != "" {
		model = v
	}
	if v := strings.Fields(g[oidDTFirmware].Str); len(v) > 0 && reFwVer.MatchString(v[0]) {
		ver = v[0]
	}
	if model == "" && strings.Contains(strings.ToLower(g[oidSysDescr].Str), "vigor") {
		model = "Vigor"
	}
	r["board-name"], r["version"], r["build"] = model, ver, g[oidDTBuild].Str
	r["sys-descr"] = g[oidSysDescr].Str
	if m, ok := g[oidDTMem]; ok && m.Num <= 100 {
		r["mem-load"] = m.Str
	}
	// CPU: hrProcessorLoad.0 is non-standard, so walk the column and take the first value
	if rows, err := d.snmp.walkTable(ctx, map[string]string{"load": oidHrCPU}); err == nil {
		idx := make([]string, 0, len(rows))
		for k := range rows {
			idx = append(idx, k)
		}
		sort.Slice(idx, func(i, j int) bool { return idxLess(idx[i], idx[j]) })
		if len(idx) > 0 {
			r["cpu-load"] = rows[idx[0]]["load"].Str
		}
	}
	d.mu.Lock()
	d.model = model
	d.mu.Unlock()
	return r, nil
}

// resourceCLI is used when SNMP is off: version via CLI, uptime via "show status".
func (d *draytekSource) resourceCLI(ctx context.Context, r Row) (Row, error) {
	if d.cli == nil {
		return nil, errors.New("chưa bật SNMP hoặc Telnet/SSH")
	}
	out, err := d.cli.Run(ctx, "sys version", "show status")
	if err != nil {
		return nil, err
	}
	v := parseSysVersion(out["sys version"])
	r["board-name"], r["version"], r["build"] = v["model"], v["version"], v["build"]
	if up, _ := parseShowStatus(out["show status"]); up > 0 {
		r["uptime"] = strconv.FormatFloat(up, 'f', 0, 64)
	}
	return r, nil
}

func (d *draytekSource) identity(ctx context.Context) ([]Row, error) {
	name := ""
	if d.snmp != nil {
		if g, err := d.snmp.get(ctx, oidSysName); err == nil {
			name = strings.TrimSpace(g[oidSysName].Str)
		}
	}
	if name == "" && d.cli != nil {
		if out, err := d.cliData(ctx); err == nil {
			name = parseSysVersion(out["sys version"])["name"]
		}
	}
	if name == "" {
		d.mu.Lock()
		name = d.model
		d.mu.Unlock()
	}
	return []Row{{"name": name}}, nil
}

// ---------- interfaces ----------

var reFwVer = regexp.MustCompile(`^\d+(\.\d+)+$`)
var reVWAN = regexp.MustCompile(`^V-WAN\d+$`)
var reWANName = regexp.MustCompile(`^WAN\d+$`)

// drayIfType gives each DrayOS interface a type the UI and events understand.
func drayIfType(name string, ifType int) string {
	switch {
	case reWANName.MatchString(name) || reVWAN.MatchString(name):
		return "wan"
	case strings.HasPrefix(name, "LAN_PORT"), strings.HasPrefix(name, "P") && len(name) <= 3:
		return "ether"
	case name == "LAN", strings.HasPrefix(name, "LAN"):
		return "bridge"
	case strings.HasPrefix(strings.ToUpper(name), "PVC"):
		return "dsl"
	case ifType == 71:
		return "wlan"
	case ifType == 23:
		return "ppp"
	case ifType == 6:
		return "ether"
	}
	return "other"
}

func (d *draytekSource) interfaces(ctx context.Context) ([]Row, error) {
	if d.snmp == nil {
		return d.interfacesCLI(ctx)
	}
	ifs, err := d.snmp.interfaces(ctx)
	if err != nil {
		return nil, err
	}
	g, _ := d.snmp.get(ctx, oidSysUpTime)
	up := float64(g[oidSysUpTime].Num) / 100

	d.mu.Lock()
	defer d.mu.Unlock()
	rebooted := up > 0 && up+5 < d.lastUp
	if up > 0 {
		d.lastUp = up
	}
	names := map[string]string{}
	var rows []Row
	for _, it := range ifs {
		names[it.Index] = it.Name
		// skip loopback and the long list of unused virtual WANs
		if it.IfType == 24 || strings.EqualFold(it.Name, "Loopback") || (reVWAN.MatchString(it.Name) && it.Admin != 1) {
			continue
		}
		rx, tx := it.RxB, it.TxB
		if !it.HC { // DrayOS only has 32-bit ifTable counters: extend them
			c := d.counters[it.Name]
			if c == nil || rebooted {
				c = &ctr64{last: [2]uint64{rx, tx}, acc: [2]uint64{rx, tx}}
				d.counters[it.Name] = c
			} else {
				for i, v := range [2]uint64{rx, tx} {
					delta := (v - c.last[i]) & 0xffffffff
					c.acc[i] += delta
					c.last[i] = v
				}
			}
			rx, tx = c.acc[0], c.acc[1]
		}
		row := Row{"name": it.Name, "type": drayIfType(it.Name, it.IfType), "running": strconv.FormatBool(it.Oper == 1),
			"disabled": strconv.FormatBool(it.Admin == 2), "mac-address": it.MAC, "comment": it.Alias,
			"rx-byte": strconv.FormatUint(rx, 10), "tx-byte": strconv.FormatUint(tx, 10), "actual-mtu": strconv.Itoa(it.MTU)}
		if it.SpeedMbps > 0 {
			row["speed"] = strconv.FormatUint(it.SpeedMbps, 10)
		}
		rows = append(rows, row)
	}
	d.ifNames = names
	return rows, nil
}

// interfacesCLI: without SNMP only the WANs are known (no byte counters).
func (d *draytekSource) interfacesCLI(ctx context.Context) ([]Row, error) {
	wans, err := d.cliWANs(ctx)
	if err != nil {
		return nil, err
	}
	var rows []Row
	for _, w := range wans {
		rows = append(rows, Row{"name": w["name"], "type": "wan", "running": strconv.FormatBool(w["status"] == "up"),
			"disabled": strconv.FormatBool(w["enabled"] == "false")})
	}
	return rows, nil
}

func (d *draytekSource) ifName(idx string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n := d.ifNames[idx]; n != "" {
		return n
	}
	return "if" + idx
}

// ---------- addresses, ARP, leases, routes ----------

func (d *draytekSource) addresses(ctx context.Context) ([]Row, error) {
	var rows []Row
	seen := map[string]bool{}
	if d.snmp != nil {
		addrs, err := d.snmp.ipAddrs(ctx)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if strings.HasPrefix(a[0], "127.") || strings.HasPrefix(a[0], "169.254.") {
				continue
			}
			bits := maskBits(a[2])
			if a[2] == "0.0.0.0" || a[2] == "" {
				bits = 32
			}
			_, nw, _ := net.ParseCIDR(a[0] + "/" + strconv.Itoa(bits))
			network := ""
			if nw != nil {
				network = nw.IP.String()
			}
			rows = append(rows, Row{"address": a[0] + "/" + strconv.Itoa(bits), "network": network, "interface": d.ifName(a[1]), "dynamic": "false"})
			seen[a[0]] = true
		}
	}
	// WAN addresses from the CLI (covers PPPoE WANs missing from ipAddrTable)
	if wans, err := d.cliWANs(ctx); err == nil {
		for _, w := range wans {
			if ip := w["address"]; ip != "" && !seen[ip] && w["status"] == "up" {
				rows = append(rows, Row{"address": ip + "/32", "network": ip, "interface": w["name"], "dynamic": "true"})
			}
		}
	}
	return rows, nil
}

func (d *draytekSource) arp(ctx context.Context) ([]Row, error) {
	if out, err := d.cliData(ctx); err == nil {
		rows := parseARP(out["ip arp status"])
		var keep []Row
		for _, r := range rows {
			if strings.HasPrefix(strings.ToUpper(r["interface"]), "WAN") {
				continue // the ISP gateway is not a LAN client
			}
			keep = append(keep, r)
		}
		return keep, nil
	}
	if d.snmp == nil {
		return nil, errNotSupported
	}
	rows, err := d.snmp.arpTable(ctx)
	if err != nil {
		return nil, errNotSupported // most DrayOS builds have no ipNetToMediaTable
	}
	for _, r := range rows {
		r["interface"] = d.ifName(r["ifindex"])
		delete(r, "ifindex")
	}
	return rows, nil
}

// bridgeHosts turns the ARP "Port" column (P1…) into switch-port locations.
func (d *draytekSource) bridgeHosts(ctx context.Context) ([]Row, error) {
	out, err := d.cliData(ctx)
	if err != nil {
		return nil, errNotSupported
	}
	var rows []Row
	for _, r := range parseARP(out["ip arp status"]) {
		if p := r["port"]; p != "" && !strings.HasPrefix(strings.ToUpper(r["interface"]), "WAN") {
			rows = append(rows, Row{"mac-address": r["mac-address"], "on-interface": p, "bridge": r["interface"], "local": "false", "dynamic": "true"})
		}
	}
	return rows, nil
}

func (d *draytekSource) routes(ctx context.Context) ([]Row, error) {
	var rows []Row
	if wans, err := d.cliWANs(ctx); err == nil {
		for _, w := range wans {
			if w["status"] == "up" && w["gateway"] != "" {
				rows = append(rows, Row{"dst-address": "0.0.0.0/0", "gateway": w["gateway"], "immediate-gw": w["gateway"] + "%" + w["name"],
					"active": "true", "dynamic": "true", "comment": w["mode"]})
			}
		}
		if len(rows) > 0 {
			return rows, nil
		}
	}
	if d.snmp == nil {
		return rows, nil
	}
	def, err := d.snmp.defaultRoutes(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range def {
		rows = append(rows, Row{"dst-address": "0.0.0.0/0", "gateway": r[0], "immediate-gw": r[0] + "%" + d.ifName(r[1]), "active": "true", "dynamic": "true"})
	}
	return rows, nil
}

// wanList reports the router's WANs (enabled ones) so the UI can suggest them.
func (d *draytekSource) wanList(ctx context.Context) ([]Row, error) {
	var rows []Row
	seen := map[string]bool{}
	if wans, err := d.cliWANs(ctx); err == nil {
		for _, w := range wans {
			if w["enabled"] != "false" && w["mode"] != "" && !seen[w["name"]] {
				rows = append(rows, Row{"list": "WAN", "interface": w["name"], "disabled": "false"})
				seen[w["name"]] = true
			}
		}
	}
	if len(rows) > 0 || d.snmp == nil {
		return rows, nil
	}
	ifs, err := d.snmp.interfaces(ctx)
	if err != nil {
		return nil, err
	}
	for _, it := range ifs {
		if reWANName.MatchString(it.Name) && it.Admin == 1 {
			rows = append(rows, Row{"list": "WAN", "interface": it.Name, "disabled": "false"})
		}
	}
	return rows, nil
}

// vpns reads connected VPN sessions from DRAYTEK-MIB (7367.2.1.<col>.<row>).
func (d *draytekSource) vpns(ctx context.Context) ([]Row, error) {
	if d.snmp == nil {
		return nil, errNotSupported
	}
	tbl, err := d.snmp.walkTable(ctx, map[string]string{
		"name": oidDTVPN + ".3", "type": oidDTVPN + ".4", "ip": oidDTVPN + ".5", "wan": oidDTVPN + ".6",
		"subnet": oidDTVPN + ".7", "txr": oidDTVPN + ".10", "rxr": oidDTVPN + ".11", "up": oidDTVPN + ".12",
	})
	if err != nil {
		return nil, err
	}
	idx := make([]string, 0, len(tbl))
	for k, r := range tbl {
		if r["name"].Str != "" {
			idx = append(idx, k)
		}
	}
	sort.Slice(idx, func(i, j int) bool { return idxLess(idx[i], idx[j]) })
	var rows []Row
	for _, k := range idx {
		r := tbl[k]
		rows = append(rows, Row{"name": r["name"].Str, "service": r["type"].Str, "caller-id": r["ip"].Str, "address": r["subnet"].Str,
			"uptime": r["up"].Str, "interface": normWAN(r["wan"].Str), "tx-rate": r["txr"].Str, "rx-rate": r["rxr"].Str})
	}
	return rows, nil
}

func (d *draytekSource) health(ctx context.Context) ([]Row, error) {
	if d.snmp == nil {
		return nil, errNotSupported
	}
	g, err := d.snmp.get(ctx, oidDTTemp)
	if err != nil {
		return nil, err
	}
	if v := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(g[oidDTTemp].Str), "C")); v != "" {
		if _, err := strconv.ParseFloat(v, 64); err == nil {
			return []Row{{"name": "temperature", "value": v, "type": "C"}}, nil
		}
	}
	return []Row{}, nil
}

// ---------- ping ----------

// Ping: WAN checks (iface set) go through the router CLI ("ip ping <ip> WANx")
// so each line is tested on its own; device checks ping from the DrayPulse host
// unless the router is set to ping by itself.
func (d *draytekSource) Ping(ctx context.Context, addr, iface string) (PingResult, error) {
	useRouter := d.cli != nil && (iface != "" || d.opts.PingFrom == "router")
	if !useRouter {
		return localPing(ctx, addr, 2)
	}
	if net.ParseIP(addr) == nil {
		return PingResult{}, errors.New("địa chỉ ping không hợp lệ")
	}
	via := "AUTO"
	if iface != "" {
		via = normWAN(iface)
	}
	cmd := "ip ping " + addr + " " + via
	out, err := d.cli.Run(ctx, cmd)
	if err != nil {
		return PingResult{}, err
	}
	res, ok := parseRouterPing(out[cmd])
	if !ok {
		return PingResult{}, fmt.Errorf("router không chạy được lệnh ping: %s", firstLine(out[cmd]))
	}
	return res, nil
}

func validDrayOpts(o *DrayOpts) error {
	switch o.SNMPVersion {
	case "":
		o.SNMPVersion = "2c"
	case "1", "2c", "3", "off":
	default:
		return errors.New("phiên bản SNMP không hợp lệ")
	}
	switch o.CLI {
	case "", "telnet", "ssh":
	default:
		return errors.New("kiểu CLI phải là telnet hoặc ssh")
	}
	if o.SNMPVersion == "off" && o.CLI == "" {
		return errors.New("cần bật ít nhất SNMP hoặc Telnet/SSH")
	}
	if err := validBlockCfg(&o.Block); err != nil {
		return err
	}
	if o.Block.Enabled && o.CLI == "" {
		return errors.New("chặn client theo MAC cần bật Telnet/SSH")
	}
	if o.SNMPPort < 0 || o.SNMPPort > 65535 || o.CLIPort < 0 || o.CLIPort > 65535 {
		return errors.New("cổng không hợp lệ")
	}
	o.SNMPUser = strings.TrimSpace(o.SNMPUser)
	if len(o.SNMPUser) > 64 {
		return errors.New("user SNMPv3 quá dài")
	}
	switch strings.ToUpper(o.AuthProto) {
	case "", "MD5", "SHA", "SHA256":
	default:
		return errors.New("giao thức xác thực SNMPv3 không hợp lệ")
	}
	switch strings.ToUpper(o.PrivProto) {
	case "", "DES", "AES":
	default:
		return errors.New("giao thức mã hoá SNMPv3 không hợp lệ")
	}
	if o.SNMPVersion != "3" {
		o.SNMPUser, o.AuthProto, o.PrivProto = "", "", ""
	}
	switch o.PingFrom {
	case "", "local":
		o.PingFrom = "local"
	case "router":
		if o.CLI == "" {
			o.PingFrom = "local"
		}
	default:
		return errors.New("nơi ping không hợp lệ")
	}
	return nil
}

package app

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// ---------- VLAN monitoring ----------
//
// "vlan status" gives each VLAN profile (index 0-15): on/off, VID, priority,
// member ports (p1…, s1… for SSIDs) and the LAN subnet it carries. "show lan"
// gives each LAN subnet with its DHCP pool. DrayPulse joins them with port
// link state (SNMP LAN_PORTn), clients (ARP/DHCP) and raises events when the
// VLAN layout changes or a DHCP pool is nearly full.

var vlanProps = []string{"id", "enabled", "vid", "pri", "ports", "subnet", "vlan-on"}
var lanProps = []string{"name", "enabled", "address", "mask", "network", "dhcp", "pool-start", "pool-size", "gateway"}

// PortView is one member port of a VLAN with its link state.
type PortView struct {
	Name    string `json:"name"`            // p1, s2 …
	Label   string `json:"label"`           // "LAN_PORT1", "SSID 2"
	Running *bool  `json:"running"`         // nil = unknown (SSID, no SNMP)
	Iface   string `json:"iface,omitempty"` // matching interface for traffic
}

type VlanView struct {
	ID       int        `json:"id"`
	VID      int        `json:"vid"`
	Pri      int        `json:"pri"`
	Enabled  bool       `json:"enabled"`
	Subnet   string     `json:"subnet"`  // LAN1…
	Network  string     `json:"network"` // 192.168.1.0/24
	Gateway  string     `json:"gateway"`
	Ports    []PortView `json:"ports"`
	PortsUp  int        `json:"portsUp"`
	Clients  int        `json:"clients"`
	Online   int        `json:"online"`
	Leases   int        `json:"leases"`
	PoolSize int        `json:"poolSize"`
}

type LanView struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Network  string `json:"network"`
	Gateway  string `json:"gateway"`
	DHCP     bool   `json:"dhcp"`
	PoolSize int    `json:"poolSize"`
	Leases   int    `json:"leases"`
	Clients  int    `json:"clients"`
	Online   int    `json:"online"`
	Vlans    []int  `json:"vlans"` // VLAN profiles carrying this subnet
}

func portLabel(p string) string {
	switch {
	case strings.HasPrefix(p, "p"):
		return "LAN_PORT" + p[1:]
	case strings.HasPrefix(p, "5gs"):
		return "SSID " + p[3:] + " (5 GHz)"
	case strings.HasPrefix(p, "s"):
		return "SSID " + p[1:]
	}
	return p
}

// vlanOf returns the VLAN profile index of a client from the ARP "VLAN" column
// ("VLAN0" → 0), or -1.
func vlanOf(c *Client) int {
	v := strings.ToUpper(strings.TrimSpace(c.VLAN))
	if n, err := strconv.Atoi(strings.TrimPrefix(v, "VLAN")); err == nil && strings.HasPrefix(v, "VLAN") {
		return n
	}
	return -1
}

func inNetwork(ip, network string) bool {
	pfx, err := netip.ParsePrefix(network)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(ip)
	return err == nil && pfx.Contains(a)
}

// vlanViews builds the VLAN and LAN tables (rs.mu held for reading).
func (rs *RState) vlanViews() ([]VlanView, []LanView) {
	lans := map[string]Row{}
	var lanOrder []string
	for _, l := range rs.Sections["lan"] {
		lans[l["name"]] = l
		lanOrder = append(lanOrder, l["name"])
	}
	leases := map[string]int{}
	for _, l := range rs.Sections["lease"] {
		leases[l["server"]]++
	}
	ifRun := map[string]bool{}
	for _, it := range rs.Ifaces {
		ifRun[it.Name] = it.Running && !it.Disabled
	}
	// clients counted per VLAN index (from ARP) and per subnet (from IP)
	byVlan, onVlan := map[int]int{}, map[int]int{}
	byLan, onLan := map[string]int{}, map[string]int{}
	anyVlanTag := false
	for _, c := range rs.Clients {
		if id := vlanOf(c); id >= 0 {
			anyVlanTag = true
			byVlan[id]++
			if c.Online {
				onVlan[id]++
			}
		}
		for _, name := range lanOrder {
			if n := lans[name]["network"]; n != "" && inNetwork(c.IP, n) {
				byLan[name]++
				if c.Online {
					onLan[name]++
				}
				break
			}
		}
	}

	vlans := []VlanView{}
	carried := map[string][]int{}
	for _, r := range rs.Sections["vlan"] {
		v := VlanView{Enabled: truthy(r["enabled"]), Subnet: r["subnet"], Ports: []PortView{}}
		v.ID, _ = strconv.Atoi(r["id"])
		v.VID, _ = strconv.Atoi(r["vid"])
		v.Pri, _ = strconv.Atoi(r["pri"])
		for _, p := range strings.Split(r["ports"], ",") {
			if p == "" {
				continue
			}
			pv := PortView{Name: p, Label: portLabel(p)}
			if strings.HasPrefix(p, "p") {
				if run, ok := ifRun[pv.Label]; ok {
					pv.Running, pv.Iface = &run, pv.Label
					if run {
						v.PortsUp++
					}
				}
			}
			v.Ports = append(v.Ports, pv)
		}
		// unused, disabled profiles are noise
		if !v.Enabled && len(v.Ports) == 0 && v.VID == 0 {
			continue
		}
		if l := lans[v.Subnet]; l != nil {
			v.Network, v.Gateway = l["network"], l["gateway"]
			v.PoolSize, _ = strconv.Atoi(l["pool-size"])
			v.Leases = leases[v.Subnet]
		}
		if anyVlanTag {
			v.Clients, v.Online = byVlan[v.ID], onVlan[v.ID]
		} else {
			v.Clients, v.Online = byLan[v.Subnet], onLan[v.Subnet]
		}
		if v.Enabled {
			carried[v.Subnet] = append(carried[v.Subnet], v.ID)
		}
		vlans = append(vlans, v)
	}
	sort.SliceStable(vlans, func(i, j int) bool {
		if vlans[i].Enabled != vlans[j].Enabled {
			return vlans[i].Enabled
		}
		return vlans[i].ID < vlans[j].ID
	})

	lanViews := []LanView{}
	for _, name := range lanOrder {
		l := lans[name]
		lv := LanView{Name: name, Enabled: truthy(l["enabled"]), Network: l["network"], Gateway: l["gateway"], DHCP: truthy(l["dhcp"]),
			Leases: leases[name], Clients: byLan[name], Online: onLan[name], Vlans: carried[name]}
		lv.PoolSize, _ = strconv.Atoi(l["pool-size"])
		if lv.Vlans == nil {
			lv.Vlans = []int{}
		}
		if !lv.Enabled && lv.Clients == 0 {
			continue
		}
		lanViews = append(lanViews, lv)
	}
	return vlans, lanViews
}

// vlanEvents reports VLAN layout changes (rs.mu held). Changes to VLANs
// are security-relevant (a port moved into another network), so they notify.
func (h *Hub) vlanEvents(rs *RState, eff *effects, prev, next []Row, now int64) {
	if len(prev) == 0 || len(next) == 0 {
		return // first read: nothing to compare
	}
	if p, n := prev[0]["vlan-on"], next[0]["vlan-on"]; p != "" && n != "" && p != n {
		state := map[string]string{"true": "BẬT", "false": "TẮT"}[n]
		eff.add(now, "warning", "🧩", "Chức năng VLAN trên router vừa được "+state, true)
	}
	old := map[string]Row{}
	for _, r := range prev {
		old[r["id"]] = r
	}
	desc := func(r Row) string {
		ports := r["ports"]
		if ports == "" {
			ports = "không cổng"
		}
		return fmt.Sprintf("VID %s, %s, %s", r["vid"], ports, firstNonEmpty(r["subnet"], "?"))
	}
	for _, r := range next {
		o := old[r["id"]]
		if o == nil {
			continue
		}
		name := "VLAN " + r["id"]
		switch {
		case o["enabled"] != r["enabled"] && truthy(r["enabled"]):
			eff.add(now, "info", "🧩", name+" được bật ("+desc(r)+")", true)
		case o["enabled"] != r["enabled"]:
			eff.add(now, "warning", "🧩", name+" bị tắt (trước đó: "+desc(o)+")", true)
		case truthy(r["enabled"]) && (o["vid"] != r["vid"] || o["ports"] != r["ports"] || o["subnet"] != r["subnet"]):
			eff.add(now, "warning", "🧩", name+" đổi cấu hình: "+desc(o)+" → "+desc(r), true)
		}
	}
	rs.dirty = true
}

// poolEvents warns when a DHCP pool is ≥ 90 % used, and clears below 80 %.
func (h *Hub) poolEvents(rs *RState, eff *effects, now int64) {
	if rs.PoolFull == nil {
		rs.PoolFull = map[string]bool{}
	}
	used := map[string]int{}
	for _, l := range rs.Sections["lease"] {
		used[l["server"]]++
	}
	for _, l := range rs.Sections["lan"] {
		name := l["name"]
		size, _ := strconv.Atoi(l["pool-size"])
		if !truthy(l["enabled"]) || !truthy(l["dhcp"]) || size < 5 {
			continue
		}
		pct := used[name] * 100 / size
		switch {
		case pct >= 90 && !rs.PoolFull[name]:
			rs.PoolFull[name], rs.dirty = true, true
			eff.add(now, "warning", "📦", fmt.Sprintf("DHCP %s sắp hết địa chỉ: %d/%d (%d%%)", name, used[name], size, pct), true)
		case pct < 80 && rs.PoolFull[name]:
			delete(rs.PoolFull, name)
			rs.dirty = true
			eff.add(now, "info", "📦", fmt.Sprintf("DHCP %s đã có lại địa chỉ trống: %d/%d", name, used[name], size), false)
		}
	}
}

// sessionEvents warns when the router's NAT session table is ≥ 85 % full
// (a common cause of "Internet is slow / pages do not open" on DrayTek)
// and clears below 70 %.
func (h *Hub) sessionEvents(rs *RState, eff *effects, rows []Row, now int64) {
	if len(rows) == 0 || rows[0]["name"] != "total" {
		return
	}
	mx, _ := strconv.Atoi(rows[0]["max"])
	cur, err := strconv.Atoi(firstNonEmpty(rows[0]["current"], rows[0]["used"]))
	if mx <= 0 || err != nil {
		return
	}
	if rs.PoolFull == nil {
		rs.PoolFull = map[string]bool{}
	}
	pct := cur * 100 / mx
	switch {
	case pct >= 85 && !rs.PoolFull["#sessions"]:
		rs.PoolFull["#sessions"], rs.dirty = true, true
		eff.add(now, "warning", "🧮", fmt.Sprintf("Bảng session NAT của router sắp đầy: %d/%d (%d%%) – mạng có thể chậm, không mở được trang web", cur, mx, pct), true)
	case pct < 70 && rs.PoolFull["#sessions"]:
		delete(rs.PoolFull, "#sessions")
		rs.dirty = true
		eff.add(now, "info", "🧮", fmt.Sprintf("Session NAT đã giảm: %d/%d (%d%%)", cur, mx, pct), false)
	}
}

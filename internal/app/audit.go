package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------- read-only configuration snapshot for audits ----------

// auditPath is one logical section read for the audit. Props is an allowlist of
// fields: anything else (keys, passwords, PSKs) is never requested.
type auditPath struct {
	Path  string
	Title string
	Props []string
	Max   int  // keep at most this many rows (the newest for logs)
	Tail  bool // keep the last rows instead of the first
}

var auditPaths = []auditPath{
	{"/system/resource", "Model, firmware, CPU, RAM", resourceProps, 1, false},
	{"/system/identity", "Tên router", []string{"name"}, 1, false},
	{"/draytek/access", "Cách DrayPulse kết nối (SNMP/CLI)", []string{"snmp-version", "snmp-community-default", "snmp-v3-level", "cli", "cli-port"}, 1, false},
	{"/draytek/wan", "Trạng thái WAN", wanStatusProps, 20, false},
	{"/interface", "Interface", []string{"name", "type", "running", "disabled", "speed", "comment"}, 100, false},
	{"/ip/address", "Địa chỉ IP", []string{"address", "network", "interface"}, 100, false},
	{"/ip/route", "Route mặc định", []string{"dst-address", "gateway", "immediate-gw", "comment"}, 20, false},
	{"/ppp/active", "Phiên VPN đang kết nối", vpnProps, 200, false},
	{"/ip/dhcp-server/lease", "DHCP lease", []string{"address", "mac-address", "host-name", "server", "expires-after"}, 300, false},
	{"/ip/arp", "Bảng ARP", []string{"address", "mac-address", "interface", "host", "port"}, 300, false},
	{"/system/health", "Cảm biến", []string{"name", "value", "type"}, 10, false},
	{"/draytek/cli/mngt rmtcfg status", "Quản trị từ Internet (mngt rmtcfg status)", []string{"line"}, 80, false},
	{"/draytek/cli/show lan", "LAN và DHCP pool (show lan)", []string{"line"}, 120, false},
	{"/draytek/cli/sys iface", "Interface IP (sys iface)", []string{"line"}, 120, false},
	{"/draytek/cli/ip dhcpc status", "DHCP client trên WAN (ip dhcpc status)", []string{"line"}, 80, false},
}

type auditSection struct {
	Title       string `json:"title"`
	Rows        []Row  `json:"rows"`
	Total       int    `json:"total"`
	Unsupported bool   `json:"unsupported,omitempty"`
	Error       string `json:"error,omitempty"`
}

type auditSnapshot struct {
	At       int64                    `json:"at"`
	Live     bool                     `json:"live"` // read from the router now; false = only data DrayPulse already had
	Sections map[string]*auditSection `json:"sections"`
}

var (
	reSecretKey = regexp.MustCompile(`(?i)(password|passwd|passphrase|secret|private-key|preshared|pre-shared|psk|wpa-pre|wpa2-pre|auth-key|token)`)
	reSecretVal = regexp.MustCompile(`(?i)((?:password|passwd|passphrase|secret|token|psk|key|user)\s*[=:]\s*)("[^"]*"|[^\s;"]+)`)
)

// redactRow drops any secret-looking field and masks inline credentials (e.g. in script sources).
func redactRow(r Row, maxVal int) Row {
	out := Row{}
	for k, v := range r {
		if reSecretKey.MatchString(k) {
			continue
		}
		v = reSecretVal.ReplaceAllString(v, "${1}***")
		if len(v) > maxVal {
			v = truncateUTF8(v, maxVal) + "…"
		}
		out[k] = v
	}
	return out
}

// collectAudit reads every audit path (read-only SNMP/CLI) from the router.
func collectAudit(ctx context.Context, src Source) *auditSnapshot {
	snap := &auditSnapshot{At: nowMs(), Live: true, Sections: map[string]*auditSection{}}
	for _, p := range auditPaths {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		rows, err := src.Fetch(cctx, p.Path, p.Props)
		cancel()
		sec := &auditSection{Title: p.Title}
		switch {
		case errors.Is(err, errNotSupported):
			sec.Unsupported = true
		case err != nil:
			sec.Error = err.Error()
		default:
			sec.Total = len(rows)
			if len(rows) > p.Max {
				if p.Tail {
					rows = rows[len(rows)-p.Max:]
				} else {
					rows = rows[:p.Max]
				}
			}
			maxVal := 300
			for _, r := range rows {
				sec.Rows = append(sec.Rows, redactRow(r, maxVal))
			}
		}
		snap.Sections[p.Path] = sec
		if ctx.Err() != nil {
			break
		}
	}
	return snap
}

// snapshotFromState builds a reduced snapshot from data DrayPulse already has.
func snapshotFromState(rs *RState) *auditSnapshot {
	snap := &auditSnapshot{At: nowMs(), Sections: map[string]*auditSection{}}
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	add := func(path, title string, rows []Row) {
		snap.Sections[path] = &auditSection{Title: title, Rows: rows, Total: len(rows)}
	}
	if rs.Resource != nil {
		add("/system/resource", "Tài nguyên hệ thống", []Row{rs.Resource})
	}
	var ifs []Row
	for _, i := range rs.Ifaces {
		ifs = append(ifs, Row{"name": i.Name, "type": i.Type, "running": strconv.FormatBool(i.Running), "disabled": strconv.FormatBool(i.Disabled)})
	}
	add("/interface", "Interface", ifs)
	add("/system/health", "Cảm biến", rs.Sections["health"])
	add("/ip/address", "Địa chỉ IP", rs.Sections["address"])
	add("/ip/route", "Route mặc định", rs.Sections["route"])
	return snap
}

func (s *auditSnapshot) rows(path string) []Row {
	if sec := s.Sections[path]; sec != nil {
		return sec.Rows
	}
	return nil
}

func (s *auditSnapshot) one(path string) Row {
	if r := s.rows(path); len(r) > 0 {
		return r[0]
	}
	return nil
}

func (s *auditSnapshot) has(path string) bool {
	sec := s.Sections[path]
	return sec != nil && !sec.Unsupported && sec.Error == ""
}

// ---------- performance & reliability stats from DrayPulse's own history ----------

type statSummary struct {
	Avg float64 `json:"avg"`
	P95 float64 `json:"p95"`
	Max float64 `json:"max"`
	N   int     `json:"samples"`
}

func summarize(vals []float64) statSummary {
	if len(vals) == 0 {
		return statSummary{}
	}
	s := append([]float64{}, vals...)
	sort.Float64s(s)
	sum := 0.0
	for _, v := range s {
		sum += v
	}
	r := func(f float64) float64 { return math.Round(f*10) / 10 }
	return statSummary{Avg: r(sum / float64(len(s))), P95: r(s[int(float64(len(s)-1)*0.95)]), Max: r(s[len(s)-1]), N: len(s)}
}

type perfStats struct {
	Hours    int                       `json:"hours"`
	CPU      statSummary               `json:"cpuPercent"`
	Mem      statSummary               `json:"memPercent"`
	Ifaces   map[string][2]statSummary `json:"interfacesBps,omitempty"` // [rx, tx]
	Warnings int                       `json:"warningEvents"`
	ByTopic  map[string]int            `json:"warningsByTopic"`
	Devices  []map[string]any          `json:"deviceAvailability,omitempty"`
}

func (h *Hub) perfStats(routerID int64, hours int, iface string) (perfStats, error) {
	out := perfStats{Hours: hours, ByTopic: map[string]int{}}
	since := nowMs() - int64(hours)*3600_000
	samples, err := h.st.Samples(routerID, since)
	if err != nil {
		return out, err
	}
	var cpu, mem []float64
	rx, tx := map[string][]float64{}, map[string][]float64{}
	for _, s := range samples {
		if s.CPU.Valid {
			cpu = append(cpu, s.CPU.Float64)
		}
		if s.Mem.Valid {
			mem = append(mem, s.Mem.Float64)
		}
		var d map[string][2]float64
		if json.Unmarshal([]byte(s.Data), &d) == nil {
			for name, v := range d {
				if iface == "" || iface == name {
					rx[name] = append(rx[name], v[0])
					tx[name] = append(tx[name], v[1])
				}
			}
		}
	}
	out.CPU, out.Mem = summarize(cpu), summarize(mem)
	out.Ifaces = map[string][2]statSummary{}
	type peak struct {
		name string
		p95  float64
	}
	var peaks []peak
	for name := range rx {
		out.Ifaces[name] = [2]statSummary{summarize(rx[name]), summarize(tx[name])}
		peaks = append(peaks, peak{name, out.Ifaces[name][0].P95 + out.Ifaces[name][1].P95})
	}
	if iface == "" && len(peaks) > 8 { // keep the 8 busiest interfaces
		sort.Slice(peaks, func(i, j int) bool { return peaks[i].p95 > peaks[j].p95 })
		for _, p := range peaks[8:] {
			delete(out.Ifaces, p.name)
		}
	}
	evs, err := h.st.ListEvents([]int64{routerID}, 2000)
	if err != nil {
		return out, err
	}
	for _, e := range evs {
		if e.At < since || e.Level != "warning" {
			continue
		}
		out.Warnings++
		topic := "khác"
		switch {
		case strings.Contains(e.Msg, "WAN"):
			topic = "WAN"
		case strings.HasPrefix(e.Msg, "Cổng"):
			topic = "cổng"
		case strings.Contains(e.Msg, "router") || strings.Contains(e.Msg, "Router"):
			topic = "router"
		case strings.Contains(e.Msg, "mất kết nối"):
			topic = "thiết bị"
		}
		out.ByTopic[topic]++
	}
	avail, err := h.st.Availability(routerID, since)
	if err == nil {
		mons, _ := h.st.ListMonitors(routerID)
		for _, m := range mons {
			if a, ok := avail[m.ID]; ok {
				out.Devices = append(out.Devices, map[string]any{"name": m.Name, "ip": m.IP, "availabilityPercent": math.Round(a*10000) / 100})
			}
		}
	}
	return out, nil
}

// ---------- built-in rule checks ----------

type Finding struct {
	Severity string   `json:"severity"` // critical | high | medium | low | info
	Area     string   `json:"area"`     // security | performance | reliability
	Title    string   `json:"title"`
	Evidence string   `json:"evidence"`
	Fix      string   `json:"fix"`
	Commands []string `json:"commands"`
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
var severityWeight = map[string]int{"critical": 30, "high": 15, "medium": 7, "low": 3, "info": 0}

// scores turns finding penalties into 0-100 with diminishing returns:
// one critical issue ≈ 67, a pile of serious issues approaches 0 without hitting it at once.
func scores(fs []Finding) (sec, perf int) {
	var ps, pp float64
	for _, f := range fs {
		if f.Area == "security" {
			ps += float64(severityWeight[f.Severity])
		} else {
			pp += float64(severityWeight[f.Severity])
		}
	}
	return int(math.Round(100 * 60 / (60 + ps))), int(math.Round(100 * 60 / (60 + pp)))
}

func on(v string) bool { return v == "true" || v == "yes" }

var reBuildDate = regexp.MustCompile(`([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{4})`)

// firmwareDate parses DrayOS build dates such as "Mar 12 2025 10:21:07".
func firmwareDate(s string) (time.Time, bool) {
	m := reBuildDate.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.Parse("Jan 2 2006", m[1]+" "+m[2]+" "+m[3])
	return t, err == nil
}

var reRmtEnabled = regexp.MustCompile(`(?i)(remote\s*(config\w*|management|access)|management from (the )?internet)\W[^\n]*\b(enabled?|on|yes|allow(ed)?)\b`)
var reRmtDisabled = regexp.MustCompile(`(?i)(remote\s*(config\w*|management|access)|management from (the )?internet)\W[^\n]*\b(disabled?|off|no|deny|denied)\b`)

func cliText(snap *auditSnapshot, cmd string) string {
	var b strings.Builder
	for _, r := range snap.rows("/draytek/cli/" + cmd) {
		b.WriteString(r["line"] + "\n")
	}
	return b.String()
}

func ruleChecks(snap *auditSnapshot, perf perfStats, wans []string) []Finding {
	var fs []Finding
	add := func(sev, area, title, evidence, fix string, cmds ...string) {
		fs = append(fs, Finding{sev, area, title, evidence, fix, cmds})
	}
	res := snap.one("/system/resource")
	acc := snap.one("/draytek/access")

	// --- how DrayPulse (and anyone else) reaches the router
	if acc != nil {
		switch acc["snmp-version"] {
		case "1", "2c":
			if on(acc["snmp-community-default"]) {
				add("high", "security", "SNMP dùng community mặc định (public/private)",
					"DrayPulse đang đọc router bằng SNMPv"+acc["snmp-version"]+" với community mặc định – ai trong mạng (hoặc từ Internet nếu mở) cũng đọc được cấu hình mạng.",
					"Vào System Maintenance → SNMP: đổi Get Community thành chuỗi khó đoán, điền Manager Host IP = IP máy DrayPulse, tắt SNMP Set nếu không dùng. Sau đó sửa community trong DrayPulse (Router → Sửa).")
			} else {
				add("low", "security", "SNMP v"+acc["snmp-version"]+" gửi community dạng rõ",
					"Community được gửi không mã hoá trong mạng.",
					"Nếu router hỗ trợ, dùng SNMPv3 (System Maintenance → SNMP → SNMPv3 Agent, chọn SHA + AES) và đổi kiểu kết nối trong DrayPulse.")
			}
		case "3":
			if acc["snmp-v3-level"] != "authPriv" {
				add("low", "security", "SNMPv3 chưa bật mã hoá", "Mức bảo mật: "+acc["snmp-v3-level"],
					"Đặt cả mật khẩu xác thực (SHA) và mã hoá (AES) cho user SNMPv3.")
			}
		}
		if acc["cli"] == "telnet" {
			add("medium", "security", "Đăng nhập router bằng Telnet (không mã hoá)",
				"DrayPulse đọc router qua Telnet: tài khoản quản trị đi qua mạng dạng rõ.",
				"Bật SSH trong System Maintenance → Management (Management Port Setup), tắt Telnet nếu không cần, rồi đổi kiểu CLI của router trong DrayPulse sang SSH.")
		}
	}
	// --- remote management from the Internet (exploited in the wild on DrayOS web UI)
	if t := cliText(snap, "mngt rmtcfg status"); strings.TrimSpace(t) != "" {
		if reRmtEnabled.MatchString(t) && !reRmtDisabled.MatchString(t) {
			add("critical", "security", "Cho phép quản trị router từ Internet",
				strings.TrimSpace(firstLine(reRmtEnabled.FindString(t))),
				"Giao diện quản trị DrayTek mở ra Internet đã nhiều lần bị khai thác hàng loạt. Tắt ở System Maintenance → Management → bỏ chọn \"Allow management from the Internet\"; nếu bắt buộc phải dùng, bật Access List chỉ cho vài IP cố định, đổi cổng, dùng HTTPS và cập nhật firmware mới nhất. Quản trị từ xa an toàn hơn qua VPN.",
				"mngt rmtcfg disable")
		}
	}
	// --- firmware age
	if res != nil {
		if t, ok := firmwareDate(res["build"] + " " + res["sys-descr"]); ok {
			age := time.Since(t)
			ev := fmt.Sprintf("%s %s, build %s (%.0f ngày trước)", res["board-name"], res["version"], t.Format("02/01/2006"), age.Hours()/24)
			fix := "Xem thông báo bảo mật tại https://www.draytek.com/about/security-advisory và tải firmware mới nhất cho đúng model; sao lưu cấu hình (System Maintenance → Configuration Backup) trước khi nâng cấp."
			switch {
			case age > 540*24*time.Hour:
				add("high", "security", "Firmware DrayOS đã cũ (hơn 18 tháng)", ev, fix)
			case age > 270*24*time.Hour:
				add("medium", "security", "Firmware DrayOS hơn 9 tháng chưa cập nhật", ev, fix)
			}
		}
	}
	// --- VPN
	for _, v := range snap.rows("/ppp/active") {
		if strings.Contains(strings.ToUpper(v["service"]), "PPTP") {
			add("medium", "security", "Còn dùng VPN PPTP: "+v["name"], "Kiểu kết nối "+v["service"],
				"PPTP có mã hoá yếu. Chuyển sang IPsec IKEv2, WireGuard, OpenVPN hoặc SSL VPN (VPN and Remote Access → Remote Dial-in User / LAN to LAN).")
			break
		}
	}
	// --- WAN health
	for _, w := range snap.rows("/draytek/wan") {
		if w["enabled"] != "false" && w["mode"] != "" && w["status"] != "up" {
			add("medium", "reliability", "WAN "+w["label"]+" đang bật nhưng mất kết nối", "Trạng thái: "+w["state"]+", kiểu "+w["mode"],
				"Kiểm tra modem/ONT, cáp, tài khoản PPPoE; nếu đường này không còn dùng thì tắt WAN đó (WAN → General Setup) để tránh failover/load-balance sai.")
		}
	}
	// --- sensors and history
	for _, s := range snap.rows("/system/health") {
		if strings.Contains(s["name"], "temperature") {
			if t, ok := parseFloat(s["value"]); ok && t >= 70 {
				add("medium", "reliability", fmt.Sprintf("Nhiệt độ cao: %.0f°C", t), "", "Kiểm tra thông gió, vị trí đặt router, nhiệt độ phòng máy.")
			}
		}
	}
	if perf.CPU.N > 30 && perf.CPU.P95 >= 80 {
		add("medium", "performance", fmt.Sprintf("CPU cao kéo dài (P95 %.0f%%, tối đa %.0f%% trong %d giờ)", perf.CPU.P95, perf.CPU.Max, perf.Hours), fmt.Sprintf("trung bình %.0f%%", perf.CPU.Avg),
			"Xem Diagnostics → Data Flow Monitor / Traffic Graph để tìm máy dùng nhiều; bật Hardware Acceleration nếu model hỗ trợ; giảm Bandwidth Management/Content Filter không cần thiết; cân nhắc model mạnh hơn.")
	}
	if perf.Mem.N > 30 && perf.Mem.Max >= 90 {
		add("medium", "performance", fmt.Sprintf("RAM gần đầy (tối đa %.0f%%)", perf.Mem.Max), fmt.Sprintf("trung bình %.0f%%", perf.Mem.Avg),
			"Kiểm tra số session NAT (Diagnostics → NAT Sessions Table), tắt tính năng không dùng; khởi động lại vào giờ thấp điểm nếu RAM tăng dần theo thời gian.")
	}
	if n := perf.ByTopic["WAN"]; n >= 6 {
		add("medium", "reliability", fmt.Sprintf("WAN chập chờn: %d cảnh báo trong %d giờ", n, perf.Hours), "Xem trang Sự kiện để biết thời điểm", "Liên hệ nhà mạng, kiểm tra modem/ONT và cáp quang; xem WAN → Internet Access → Details Page.")
	}
	for _, d := range perf.Devices {
		if a, _ := d["availabilityPercent"].(float64); a < 98 {
			add("low", "reliability", fmt.Sprintf("Thiết bị %v (%v) chỉ sẵn sàng %.1f%%", d["name"], d["ip"], a), "", "Kiểm tra nguồn, cáp và cổng switch của thiết bị.")
		}
	}
	sort.SliceStable(fs, func(i, j int) bool { return severityRank[fs[i].Severity] < severityRank[fs[j].Severity] })
	return fs
}

func countChain(rows []Row, chain string) (n int) {
	for _, r := range rows {
		if r["chain"] == chain && !on(r["disabled"]) {
			n++
		}
	}
	return
}

func orAll(a string) string {
	if a == "" {
		return "(mọi địa chỉ)"
	}
	return a
}

func num(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

func topCounts(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool { return l[i].v > l[j].v })
	var parts []string
	for i, x := range l {
		if i == n {
			break
		}
		parts = append(parts, fmt.Sprintf("%s: %d lần", x.k, x.v))
	}
	return strings.Join(parts, "; ")
}

// versionLess compares firmware versions like "4.4.5.2" < "4.5.1".
func versionLess(a, b string) bool {
	pa, pb := strings.Split(strings.Fields(a + " ")[0], "."), strings.Split(strings.Fields(b + " ")[0], ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(strings.TrimLeft(pa[i], "rcbeta"))
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(strings.TrimLeft(pb[i], "rcbeta"))
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// ---------- anonymiser: public IPs and MACs never leave the server ----------

type anonymizer struct {
	fwd  map[string]string
	rev  map[string]string
	n    map[string]int
	keep map[string]bool // dotted strings that are not addresses (firmware versions)
}

// Keep marks strings that look like IPv4 but are not (e.g. DrayOS "4.4.5.2").
func (a *anonymizer) Keep(vals ...string) {
	if a == nil {
		return
	}
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			a.keep[v] = true
		}
	}
}

// reVerBefore: a dotted number right after "Version:", "DrayOS", "firmware"…
// is a firmware version, not an address.
var reVerBefore = regexp.MustCompile(`(?i)(version|drayos|firmware|fw|ver)\s*[:=]?\s*v?$`)

var (
	reIPv4 = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reMAC  = regexp.MustCompile(`\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b`)
)

func newAnonymizer() *anonymizer {
	return &anonymizer{fwd: map[string]string{}, rev: map[string]string{}, n: map[string]int{}, keep: map[string]bool{}}
}

func (a *anonymizer) token(kind, v string) string {
	if t, ok := a.fwd[v]; ok {
		return t
	}
	a.n[kind]++
	t := fmt.Sprintf("%s-%d", kind, a.n[kind])
	a.fwd[v], a.rev[t] = t, v
	return t
}

func (a *anonymizer) Mask(s string) string {
	if a == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, loc := range reIPv4.FindAllStringIndex(s, -1) {
		m := s[loc[0]:loc[1]]
		b.WriteString(s[last:loc[0]])
		last = loc[1]
		if a.keep[m] || reVerBefore.MatchString(s[max(0, loc[0]-12):loc[0]]) {
			b.WriteString(m)
			continue
		}
		b.WriteString(a.maskIP(m))
	}
	b.WriteString(s[last:])
	s = b.String()
	return reMAC.ReplaceAllStringFunc(s, func(m string) string { return a.token("MAC", strings.ToUpper(m)) })
}

func (a *anonymizer) maskIP(m string) string {
	ip, err := netip.ParseAddr(m)
	if err != nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return m
	}
	if b := ip.As4(); b[0] == 100 && b[1]&0xC0 == 64 { // CGNAT 100.64/10 is not public either
		return m
	}
	if m == "8.8.8.8" || m == "1.1.1.1" || m == "8.8.4.4" || m == "1.0.0.1" {
		return m // well-known resolvers carry no private information
	}
	return a.token("PUBLIC-IP", m)
}

func (a *anonymizer) Unmask(s string) string {
	if a == nil || len(a.rev) == 0 {
		return s
	}
	keys := make([]string, 0, len(a.rev))
	for k := range a.rev {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) }) // PUBLIC-IP-12 before PUBLIC-IP-1
	for _, k := range keys {
		s = strings.ReplaceAll(s, k, a.rev[k])
	}
	return s
}

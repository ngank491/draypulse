package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestRosSeconds(t *testing.T) {
	cases := map[string]float64{
		"1w2d3h4m5s": 604800 + 2*86400 + 3*3600 + 4*60 + 5,
		"2d03:04:05": 2*86400 + 3*3600 + 4*60 + 5,
		"03:04:05":   3*3600 + 4*60 + 5,
		"10ms":       0.010,
		"1ms500us":   0.0015,
		"5m":         300,
		"":           0,
	}
	for in, want := range cases {
		if got := rosSeconds(in); (got-want) > 1e-9 || (want-got) > 1e-9 {
			t.Errorf("rosSeconds(%q)=%v want %v", in, got, want)
		}
	}
}

func TestProbeHysteresis(t *testing.T) {
	p := newProbe()
	if tr := p.step(false, false, 1, -1, 2); tr != "" {
		t.Fatal("one failure must not alert")
	}
	if tr := p.step(false, true, 2, -1, 2); tr != "" || p.Fails != 1 {
		t.Fatal("errored check must not count")
	}
	if tr := p.step(false, false, 3, -1, 2); tr != "down" {
		t.Fatal("two failures must go down")
	}
	if tr := p.step(false, false, 4, -1, 2); tr != "" {
		t.Fatal("already down must not re-alert")
	}
	if tr := p.step(true, false, 5, 3, 2); tr != "up" || p.Since != 5 {
		t.Fatal("success must recover")
	}
	q := newProbe()
	if tr := q.step(true, false, 1, 1, 2); tr != "" || q.Status != "up" {
		t.Fatal("unknown->up is silent")
	}
}

func TestDetectWANs(t *testing.T) {
	got := detectWANs(map[string][]Row{
		"pppoe_client": {{"name": "pppoe-out1", "interface": "ether1"}},
		"dhcp_client":  {{"interface": "ether2", "add-default-route": "yes"}, {"interface": "bridge", "add-default-route": "no"}},
		"route":        {{"immediate-gw": "10.0.0.1%ether1"}, {"gateway": "pppoe-out1"}},
		"wan_list":     {{"interface": "lte1"}},
	})
	want := "lte1,pppoe-out1,ether2"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v want %s", got, want)
	}
}

func TestPasswordAndBox(t *testing.T) {
	h := hashPassword("correct horse battery")
	if !verifyPassword(h, "correct horse battery") || verifyPassword(h, "wrong") {
		t.Fatal("password verify")
	}
	box, err := LoadBox(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	sealed := box.Seal("secret")
	if out, err := box.Open(sealed); err != nil || out != "secret" {
		t.Fatal("box roundtrip", err)
	}
	if _, err := box.Open(sealed[:len(sealed)-2] + "AA"); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
}

func TestAccumRates(t *testing.T) {
	var a accum
	r1 := 8e6
	ifs := []Iface{{Name: "ether1", RxBps: &r1, TxBps: &r1}}
	if s := a.add(60_000, nil, nil, ifs); s != nil {
		t.Fatal("first sample should not flush")
	}
	a.add(90_000, nil, nil, ifs)
	s := a.add(120_000, nil, nil, ifs)
	if s == nil || s.at != 60_000 || !strings.Contains(string(s.data), `"ether1":[8000000,8000000]`) {
		t.Fatalf("flush got %+v", s)
	}
}

func itoa(n uint64) string { b, _ := json.Marshal(n); return string(b) }

type harness struct {
	t   *testing.T
	srv *Server
	hub *Hub
	st  *Store
	web *httptest.Server
	c   *http.Client
}

func newHarness(t *testing.T) *harness {
	dir := t.TempDir()
	st, err := OpenStore(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, _ := LoadBox(filepath.Join(dir, "key"))
	settings, _ := NewSettingsStore(st, box)
	cfg := &Config{DataDir: dir}
	srv := &Server{cfg: cfg, st: st, box: box, settings: settings, lim: newLimiter(), pwSem: make(chan struct{}, 2), setupCode: "ABCD-EFGH"}
	hub := NewHub(st, box, settings, false)
	n := NewNotifier(st, settings)
	hub.notify, n.hub, srv.hub, srv.n = n, hub, hub, n
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); hub.Wait() })
	if err := hub.Start(ctx); err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(srv.Handler())
	t.Cleanup(web.Close)
	jar, _ := cookiejar.New(nil)
	return &harness{t, srv, hub, st, web, &http.Client{Jar: jar}}
}

func (h *harness) call(method, path string, body any, out any) int {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, h.web.URL+path, rd)
	req.Header.Set("X-Requested-With", "draypulse")
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func waitFor(t *testing.T, what string, cond func() bool) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestSetupLoginAndCSRF(t *testing.T) {
	h := newHarness(t)
	if code := h.call("GET", "/api/overview", nil, nil); code != 401 {
		t.Fatalf("anon overview = %d", code)
	}
	if code := h.call("POST", "/api/setup", map[string]string{"code": "WRONG", "username": "admin", "password": "0123456789"}, nil); code != 403 {
		t.Fatalf("bad setup code = %d", code)
	}
	codeFile := filepath.Join(h.srv.cfg.DataDir, setupCodeFile)
	writeFileAtomic(codeFile, []byte("ABCD-EFGH\n"), 0o600)
	if code := h.call("POST", "/api/setup", map[string]string{"code": "abcd-efgh", "username": "admin", "password": "0123456789"}, nil); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	if _, err := os.Stat(codeFile); !os.IsNotExist(err) {
		t.Fatal("setup code file must be removed after setup")
	}
	if code := h.call("POST", "/api/setup", map[string]string{"code": "abcd-efgh", "username": "x2", "password": "0123456789"}, nil); code != 409 {
		t.Fatalf("second setup = %d", code)
	}
	// mutating request without the anti-CSRF header is refused
	req, _ := http.NewRequest("POST", h.web.URL+"/api/admin/routers", strings.NewReader(`{}`))
	resp, _ := h.c.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("csrf = %d", resp.StatusCode)
	}
	// viewer cannot reach admin APIs or routers not granted
	var created map[string]int64
	h.call("POST", "/api/admin/users", map[string]any{"username": "bob", "password": "viewerpass1", "role": "viewer", "routers": []int64{}}, &created)
	h.call("POST", "/api/logout", nil, nil)
	if code := h.call("POST", "/api/login", map[string]string{"username": "bob", "password": "viewerpass1"}, nil); code != 200 {
		t.Fatalf("viewer login = %d", code)
	}
	if code := h.call("GET", "/api/admin/routers", nil, nil); code != 403 {
		t.Fatalf("viewer admin = %d", code)
	}
	// brute force lockout
	h.call("POST", "/api/logout", nil, nil)
	for i := 0; i < 5; i++ {
		h.call("POST", "/api/login", map[string]string{"username": "admin", "password": "nope"}, nil)
	}
	if code := h.call("POST", "/api/login", map[string]string{"username": "admin", "password": "0123456789"}, nil); code != 429 {
		t.Fatalf("lockout = %d", code)
	}
}

// ---------- end-to-end: simulated DrayTek (SNMP + Telnet) + real HTTP server ----------

func TestPullEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	rx, wanUp := uint(4294960000), true
	snmp, err := startSimSNMP(ctx, "s3cret-ro", func() map[string]gosnmp.SnmpPDU {
		mu.Lock()
		defer mu.Unlock()
		rx += 100000
		oper := map[bool]int{true: 1, false: 2}[wanUp]
		return map[string]gosnmp.SnmpPDU{
			oidSysDescr:  pduStr("DrayTek Corporation, Router Model: Vigor2865, Version: 4.4.6, Build Date/Time:Jan 10 2023 14:04:32"),
			oidSysUpTime: pduTicks(9_000_000), oidSysName: pduStr("TestRouter"),
			oidDTMem: pduInt(75), oidHrCPU + ".0": pduInt(7),
			"1.3.6.1.2.1.2.2.1.2.1": pduStr("LAN"), "1.3.6.1.2.1.2.2.1.2.4": pduStr("WAN1"), "1.3.6.1.2.1.2.2.1.2.11": pduStr("V-WAN8"),
			"1.3.6.1.2.1.2.2.1.3.1": pduInt(6), "1.3.6.1.2.1.2.2.1.3.4": pduInt(6), "1.3.6.1.2.1.2.2.1.3.11": pduInt(53),
			"1.3.6.1.2.1.2.2.1.7.1": pduInt(1), "1.3.6.1.2.1.2.2.1.7.4": pduInt(1), "1.3.6.1.2.1.2.2.1.7.11": pduInt(2),
			"1.3.6.1.2.1.2.2.1.8.1": pduInt(1), "1.3.6.1.2.1.2.2.1.8.4": pduInt(oper), "1.3.6.1.2.1.2.2.1.8.11": pduInt(2),
			"1.3.6.1.2.1.2.2.1.10.1": pduC32(5), "1.3.6.1.2.1.2.2.1.10.4": pduC32(rx), "1.3.6.1.2.1.2.2.1.16.4": pduC32(100),
			oidDTVPN + ".3.1": pduStr("hcm (lan2lan)"), oidDTVPN + ".4.1": pduStr("PPTP"), oidDTVPN + ".5.1": pduIP("14.161.7.22"),
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := startSimCLI(ctx, "TestRouter", "admin", "pw", func(cmd string) string {
		switch cmd {
		case "sys version":
			return "Router Model: Vigor2865    Version: 4.4.6 English\nRouter Name: TestRouter\n"
		case "wan status":
			return "WAN1: Online, stall=N\n Mode: PPPoE, Up Time=10:00:00\n IP=113.161.20.45, GW IP=113.161.1.1\n"
		case "ip arp status":
			return "Index IP Address     MAC Address      HOST ID    Interface  VLAN   Port\n   1   10.0.0.9       BC-32-5F-00-00-11  CAM1  LAN1   VLAN0   P3\n"
		case "srv dhcp status":
			return "LAN1\n1       10.0.0.9    BC-32-5F-00-00-11       10:00:00        CAM1\n"
		}
		return "% Unknown command"
	})
	if err != nil {
		t.Fatal(err)
	}

	h := newHarness(t)
	h.call("POST", "/api/setup", map[string]string{"code": "ABCD-EFGH", "username": "admin", "password": "0123456789"}, nil)
	in := map[string]any{"name": "R1", "mode": "pull", "host": "127.0.0.1", "username": "admin", "password": "pw", "interval": 5,
		"opts": map[string]any{"snmpVersion": "2c", "snmpPort": snmp.Port(), "cli": "telnet", "cliPort": cli.Port()},
		"snmp": map[string]any{"community": "s3cret-ro"},
		"wans": []WAN{{Iface: "WAN1", Label: "VNPT"}}, "enabled": true}
	var rt Router
	if code := h.call("POST", "/api/admin/routers", in, &rt); code != 200 || rt.ID == 0 || !rt.HasSNMPSecret || !rt.HasPassword || rt.Opts.CLI != "telnet" {
		t.Fatalf("create router = %d %+v", code, rt)
	}
	// missing community must be rejected for a new router
	bad := map[string]any{"name": "X", "mode": "pull", "host": "127.0.0.1", "opts": map[string]any{"snmpVersion": "2c"}, "enabled": true}
	if code := h.call("POST", "/api/admin/routers", bad, nil); code != 400 {
		t.Fatalf("router without community = %d", code)
	}
	var test map[string]any
	if code := h.call("POST", "/api/admin/routers/test", map[string]any{"id": rt.ID, "host": "127.0.0.1", "username": "admin",
		"opts": map[string]any{"snmpVersion": "2c", "snmpPort": snmp.Port(), "cli": "telnet", "cliPort": cli.Port()}}, &test); code != 200 ||
		test["identity"] != "TestRouter" || test["board"] != "Vigor2865" || test["cli"] != "Vigor2865 4.4.6" {
		t.Fatalf("test connection = %d %v", code, test)
	}
	h.call("POST", "/api/admin/routers/"+itoa(uint64(rt.ID))+"/monitors", map[string]any{"name": "Loopback", "ip": "127.0.0.1", "kind": "server", "enabled": true, "notify": true}, nil)
	h.hub.ReloadMonitors(rt.ID)

	var det struct{ Router RouterView }
	waitFor(t, "router up with sections", func() bool {
		h.call("GET", "/api/routers/"+itoa(uint64(rt.ID)), nil, &det)
		return det.Router.Status == "up" && det.Router.Identity == "TestRouter" && len(det.Router.Sections["wan_status"]) == 1
	})
	if len(det.Router.Ifaces) != 2 {
		t.Fatalf("unused virtual WANs must be hidden: %+v", det.Router.Ifaces)
	}
	if det.Router.Mem == nil || *det.Router.Mem != 75 || det.Router.CPU == nil || *det.Router.CPU != 7 {
		t.Fatalf("cpu/mem = %v %v", det.Router.CPU, det.Router.Mem)
	}
	if v := det.Router.Sections["ppp_active"]; len(v) != 1 || v[0]["service"] != "PPTP" {
		t.Fatalf("vpn = %+v", v)
	}
	if len(det.Router.WANs) == 0 || det.Router.WANs[0].PublicIP != "113.161.20.45" {
		t.Fatalf("wan public ip = %+v", det.Router.WANs)
	}
	waitFor(t, "client from DHCP/ARP", func() bool {
		h.call("GET", "/api/routers/"+itoa(uint64(rt.ID)), nil, &det)
		for _, c := range det.Router.Clients {
			if c.MAC == "BC:32:5F:00:00:11" && c.Port == "P3" && c.Host == "CAM1" {
				return true
			}
		}
		return false
	})

	// WAN link loss needs two consecutive samples
	rs := h.hub.get(rt.ID)
	mu.Lock()
	wanUp = false
	mu.Unlock()
	h.hub.observeFast(rs, Row{"uptime": "90000"}, []Row{{"name": "WAN1", "type": "wan", "running": "false", "rx-byte": "1", "tx-byte": "1"}}, nowMs())
	if rs.WANs["WAN1"].Link.Status == "down" {
		t.Fatal("one sample must not mark link down")
	}
	h.hub.observeFast(rs, Row{"uptime": "90010"}, []Row{{"name": "WAN1", "type": "wan", "running": "false", "rx-byte": "1", "tx-byte": "1"}}, nowMs())
	if rs.WANs["WAN1"].Link.Status != "down" {
		t.Fatal("two samples must mark link down")
	}
	// Telegram alert was queued even though no bot is configured yet (kept up to 24h)
	h.srv.settings.Update(SettingsInput{AdminChat: "123", SummaryAt: "08:00", RepeatMin: 30, Timezone: "Asia/Ho_Chi_Minh", RetentionDays: 30})
	h.hub.observeFast(rs, Row{"uptime": "90020"}, []Row{{"name": "WAN1", "type": "wan", "running": "true", "rx-byte": "1", "tx-byte": "1"}}, nowMs())
	msgs, _ := h.st.DueOutbox(nowMs()+1, 10)
	if len(msgs) == 0 || !strings.Contains(msgs[len(msgs)-1].Text, "[R1] WAN VNPT (WAN1): link phục hồi") {
		t.Fatalf("outbox = %+v", msgs)
	}

	// the secrets never come back from the admin API
	var list struct{ Routers []map[string]any }
	h.call("GET", "/api/admin/routers", nil, &list)
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), "s3cret-ro") || strings.Contains(string(b), `"pw"`) {
		t.Fatalf("secret leaked: %s", b)
	}
}

// A new router without devices or data must still send empty collections,
// the UI calls .map/.filter on them.
func TestEmptyRouterViewJSON(t *testing.T) {
	h := newHarness(t)
	h.call("POST", "/api/setup", map[string]string{"code": "ABCD-EFGH", "username": "admin", "password": "0123456789"}, nil)
	var rt Router
	h.call("POST", "/api/admin/routers", map[string]any{"name": "Empty", "mode": "pull", "host": "192.0.2.1", "opts": map[string]any{"snmpVersion": "2c"}, "snmp": map[string]any{"community": "x"}, "enabled": false}, &rt)
	req, _ := http.NewRequest("GET", h.web.URL+"/api/routers/"+itoa(uint64(rt.ID)), nil)
	resp, err := h.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{`"monitors":[]`, `"ifaces":[]`, `"sections":{}`, `"wans":[]`, `"downList":[]`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %s in %s", want, body)
		}
	}
}

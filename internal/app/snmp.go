package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// ---------- small SNMP client (read-only: GET / GETNEXT / GETBULK) ----------

// SNMPConfig is what DrayPulse needs to talk SNMP to one router.
type SNMPConfig struct {
	Host      string
	Port      int    // default 161
	Version   string // "2c" (default) | "1" | "3"
	Community string // v1/v2c
	// SNMPv3 (USM). Level is derived: no auth pass → noAuthNoPriv, no priv pass → authNoPriv.
	User      string
	AuthProto string // MD5 | SHA (default) | SHA256
	AuthPass  string
	PrivProto string // DES | AES (default)
	PrivPass  string
}

type snmpClient struct {
	cfg SNMPConfig
}

func newSNMPClient(cfg SNMPConfig) *snmpClient {
	if cfg.Port == 0 {
		cfg.Port = 161
	}
	if cfg.Version == "" {
		cfg.Version = "2c"
	}
	return &snmpClient{cfg: cfg}
}

// session opens one UDP "connection" used for a batch of requests.
func (c *snmpClient) session(ctx context.Context) (*gosnmp.GoSNMP, error) {
	g := &gosnmp.GoSNMP{
		Target:             c.cfg.Host,
		Port:               uint16(c.cfg.Port),
		Timeout:            3 * time.Second,
		Retries:            1,
		Context:            ctx,
		MaxOids:            gosnmp.MaxOids,
		MaxRepetitions:     20,
		ExponentialTimeout: false,
	}
	switch c.cfg.Version {
	case "1":
		g.Version, g.Community = gosnmp.Version1, c.cfg.Community
	case "3":
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		usm := &gosnmp.UsmSecurityParameters{UserName: c.cfg.User}
		g.MsgFlags = gosnmp.NoAuthNoPriv
		if c.cfg.AuthPass != "" {
			g.MsgFlags = gosnmp.AuthNoPriv
			usm.AuthenticationPassphrase = c.cfg.AuthPass
			switch strings.ToUpper(c.cfg.AuthProto) {
			case "MD5":
				usm.AuthenticationProtocol = gosnmp.MD5
			case "SHA256", "SHA-256":
				usm.AuthenticationProtocol = gosnmp.SHA256
			default:
				usm.AuthenticationProtocol = gosnmp.SHA
			}
			if c.cfg.PrivPass != "" {
				g.MsgFlags = gosnmp.AuthPriv
				usm.PrivacyPassphrase = c.cfg.PrivPass
				if strings.ToUpper(c.cfg.PrivProto) == "DES" {
					usm.PrivacyProtocol = gosnmp.DES
				} else {
					usm.PrivacyProtocol = gosnmp.AES
				}
			}
		}
		g.SecurityParameters = usm
	default:
		g.Version, g.Community = gosnmp.Version2c, c.cfg.Community
	}
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < g.Timeout*2 {
			g.Timeout = max(left/2, 500*time.Millisecond)
		}
	}
	if err := g.Connect(); err != nil {
		return nil, friendlySNMPErr(err)
	}
	return g, nil
}

func friendlySNMPErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.New("router không trả lời SNMP (timeout)")
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "i/o timeout"):
		return errors.New("router không trả lời SNMP (timeout): kiểm tra SNMP đã bật, community/user đúng và IP máy DrayPulse nằm trong danh sách được phép")
	case strings.Contains(msg, "connection refused"):
		return errors.New("router từ chối SNMP (cổng UDP 161 đóng)")
	case strings.Contains(msg, "no route to host"), strings.Contains(msg, "network is unreachable"):
		return errors.New("không có đường tới router")
	case strings.Contains(msg, "unknown user"), strings.Contains(msg, "wrong digest"), strings.Contains(msg, "authentication"):
		return errors.New("SNMPv3: sai user hoặc mật khẩu xác thực/mã hoá")
	}
	return fmt.Errorf("lỗi SNMP: %v", err)
}

// snmpVal is one value normalised to string form.
type snmpVal struct {
	Type gosnmp.Asn1BER
	Str  string // printable string / decimal number / dotted OID
	Raw  []byte // octet strings (for MAC addresses)
	Num  uint64
	OK   bool
}

func convPDU(p gosnmp.SnmpPDU) snmpVal {
	v := snmpVal{Type: p.Type}
	switch p.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		return v
	case gosnmp.OctetString:
		b, _ := p.Value.([]byte)
		v.Raw, v.Str, v.OK = b, printable(b), true
	case gosnmp.ObjectIdentifier:
		s, _ := p.Value.(string)
		v.Str, v.OK = strings.TrimPrefix(s, "."), true
	case gosnmp.IPAddress:
		s, _ := p.Value.(string)
		v.Str, v.OK = s, true
	default:
		n := gosnmp.ToBigInt(p.Value)
		if n.Sign() < 0 {
			v.Str, v.OK = n.String(), true
			return v
		}
		v.Num, v.Str, v.OK = n.Uint64(), n.String(), true
	}
	return v
}

// printable decodes SNMP strings, dropping trailing NULs and control bytes.
func printable(b []byte) string {
	s := strings.TrimRight(string(b), "\x00")
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// get reads scalar OIDs; missing ones are simply absent from the map.
func (c *snmpClient) get(ctx context.Context, oids ...string) (map[string]snmpVal, error) {
	g, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	defer g.Conn.Close()
	out := map[string]snmpVal{}
	for i := 0; i < len(oids); i += 10 {
		chunk := oids[i:min(i+10, len(oids))]
		pkt, err := g.Get(chunk)
		if err != nil {
			return nil, friendlySNMPErr(err)
		}
		if pkt.Error != gosnmp.NoError && c.cfg.Version == "1" {
			// v1 fails the whole request on one missing OID: retry one by one
			for _, o := range chunk {
				if p, err := g.Get([]string{o}); err == nil && p.Error == gosnmp.NoError && len(p.Variables) == 1 {
					if v := convPDU(p.Variables[0]); v.OK {
						out[o] = v
					}
				}
			}
			continue
		}
		for _, p := range pkt.Variables {
			if v := convPDU(p); v.OK {
				out[strings.TrimPrefix(p.Name, ".")] = v
			}
		}
	}
	return out, nil
}

// walkTable walks several columns of one table and groups them by row index
// (the OID suffix after the column). Columns the router lacks are skipped.
func (c *snmpClient) walkTable(ctx context.Context, cols map[string]string) (map[string]map[string]snmpVal, error) {
	g, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	defer g.Conn.Close()
	rows := map[string]map[string]snmpVal{}
	got := false
	for name, oid := range cols {
		var pdus []gosnmp.SnmpPDU
		if g.Version == gosnmp.Version1 {
			pdus, err = g.WalkAll(oid)
		} else {
			pdus, err = g.BulkWalkAll(oid)
		}
		if err != nil {
			if ctx.Err() != nil || !got && strings.Contains(err.Error(), "timeout") {
				return nil, friendlySNMPErr(err)
			}
			continue
		}
		got = true
		prefix := "." + oid + "."
		for _, p := range pdus {
			if !strings.HasPrefix(p.Name, prefix) {
				continue
			}
			v := convPDU(p)
			if !v.OK {
				continue
			}
			idx := p.Name[len(prefix):]
			if rows[idx] == nil {
				rows[idx] = map[string]snmpVal{}
			}
			rows[idx][name] = v
			if len(rows) > maxSectionRows {
				break
			}
		}
	}
	return rows, nil
}

// ---------- standard MIB helpers ----------

const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysContact  = "1.3.6.1.2.1.1.4.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"
)

var ifCols = map[string]string{
	"descr":  "1.3.6.1.2.1.2.2.1.2",
	"type":   "1.3.6.1.2.1.2.2.1.3",
	"mtu":    "1.3.6.1.2.1.2.2.1.4",
	"speed":  "1.3.6.1.2.1.2.2.1.5",
	"mac":    "1.3.6.1.2.1.2.2.1.6",
	"admin":  "1.3.6.1.2.1.2.2.1.7",
	"oper":   "1.3.6.1.2.1.2.2.1.8",
	"in":     "1.3.6.1.2.1.2.2.1.10",
	"out":    "1.3.6.1.2.1.2.2.1.16",
	"name":   "1.3.6.1.2.1.31.1.1.1.1",
	"hcin":   "1.3.6.1.2.1.31.1.1.1.6",
	"hcout":  "1.3.6.1.2.1.31.1.1.1.10",
	"hspeed": "1.3.6.1.2.1.31.1.1.1.15",
	"alias":  "1.3.6.1.2.1.31.1.1.1.18",
}

// snmpIface is one interface from IF-MIB.
type snmpIface struct {
	Index       string
	Name, Descr string
	Alias       string
	IfType      int
	MAC         string
	Admin, Oper int
	RxB, TxB    uint64
	HC          bool
	SpeedMbps   uint64
	MTU         int
}

func (c *snmpClient) interfaces(ctx context.Context) ([]snmpIface, error) {
	rows, err := c.walkTable(ctx, ifCols)
	if err != nil {
		return nil, err
	}
	var out []snmpIface
	for idx, r := range rows {
		it := snmpIface{Index: idx, Name: strings.TrimSpace(r["name"].Str), Descr: strings.TrimSpace(r["descr"].Str), Alias: strings.TrimSpace(r["alias"].Str),
			IfType: int(r["type"].Num), Admin: int(r["admin"].Num), Oper: int(r["oper"].Num), MTU: int(r["mtu"].Num)}
		if it.Name == "" {
			it.Name = it.Descr
		}
		if it.Name == "" {
			it.Name = "if" + idx
		}
		if len(r["mac"].Raw) == 6 {
			it.MAC = fmtMAC(r["mac"].Raw)
		}
		if v, ok := r["hcin"]; ok && v.OK {
			it.RxB, it.TxB, it.HC = v.Num, r["hcout"].Num, true
		} else {
			it.RxB, it.TxB = r["in"].Num, r["out"].Num
		}
		if v := r["hspeed"]; v.OK && v.Num > 0 {
			it.SpeedMbps = v.Num
		} else if v := r["speed"]; v.OK {
			it.SpeedMbps = v.Num / 1e6
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return idxLess(out[i].Index, out[j].Index) })
	return out, nil
}

func idxLess(a, b string) bool {
	x, e1 := strconv.Atoi(a)
	y, e2 := strconv.Atoi(b)
	if e1 == nil && e2 == nil {
		return x < y
	}
	return a < b
}

func fmtMAC(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	return strings.ToUpper(net.HardwareAddr(b).String())
}

// ipAddrs reads IP-MIB ipAddrTable: address → (ifIndex, mask).
func (c *snmpClient) ipAddrs(ctx context.Context) ([][3]string, error) {
	rows, err := c.walkTable(ctx, map[string]string{
		"if":   "1.3.6.1.2.1.4.20.1.2",
		"mask": "1.3.6.1.2.1.4.20.1.3",
	})
	if err != nil {
		return nil, err
	}
	var out [][3]string
	for idx, r := range rows {
		if net.ParseIP(idx) == nil {
			continue
		}
		out = append(out, [3]string{idx, r["if"].Str, r["mask"].Str})
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i][0], out[j][0]) })
	return out, nil
}

// arpTable reads ipNetToMediaTable: index is ifIndex.a.b.c.d.
func (c *snmpClient) arpTable(ctx context.Context) ([]Row, error) {
	rows, err := c.walkTable(ctx, map[string]string{
		"mac":  "1.3.6.1.2.1.4.22.1.2",
		"type": "1.3.6.1.2.1.4.22.1.4",
	})
	if err != nil {
		return nil, err
	}
	var out []Row
	for idx, r := range rows {
		parts := strings.SplitN(idx, ".", 2)
		if len(parts) != 2 || net.ParseIP(parts[1]) == nil {
			continue
		}
		mac := fmtMAC(r["mac"].Raw)
		if mac == "" || mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF" {
			continue
		}
		row := Row{"address": parts[1], "mac-address": mac, "ifindex": parts[0], "status": "reachable", "dynamic": "true"}
		switch r["type"].Num {
		case 2: // invalid
			row["invalid"], row["status"] = "true", "failed"
		case 4: // static
			row["dynamic"] = "false"
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i]["address"], out[j]["address"]) })
	return out, nil
}

// defaultRoutes reads the default route(s) from ipCidrRouteTable, falling
// back to the older ipRouteTable.
func (c *snmpClient) defaultRoutes(ctx context.Context) ([][2]string, error) {
	rows, err := c.walkTable(ctx, map[string]string{
		"if": "1.3.6.1.2.1.4.24.4.1.5.0.0.0.0", // ipCidrRouteIfIndex.0.0.0.0.*
	})
	if err != nil {
		return nil, err
	}
	var out [][2]string // gateway, ifIndex
	for idx, r := range rows {
		// idx = mask(4).tos(1).nexthop(4)
		p := strings.Split(idx, ".")
		if len(p) == 9 && strings.Join(p[:4], ".") == "0.0.0.0" {
			out = append(out, [2]string{strings.Join(p[5:], "."), r["if"].Str})
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	g, err := c.get(ctx, "1.3.6.1.2.1.4.21.1.7.0.0.0.0", "1.3.6.1.2.1.4.21.1.2.0.0.0.0")
	if err != nil {
		return nil, err
	}
	if gw, ok := g["1.3.6.1.2.1.4.21.1.7.0.0.0.0"]; ok && gw.Str != "0.0.0.0" {
		out = append(out, [2]string{gw.Str, g["1.3.6.1.2.1.4.21.1.2.0.0.0.0"].Str})
	}
	return out, nil
}

func maskBits(mask string) int {
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		return 32
	}
	ones, _ := net.IPMask(ip).Size()
	return ones
}

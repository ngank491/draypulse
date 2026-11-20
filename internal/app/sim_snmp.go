package app

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/gosnmp/gosnmp"
)

// simSNMP is a tiny SNMPv1/v2c agent used by the demo router and the tests.
// It answers GET, GETNEXT and GETBULK from an OID table that a callback
// refreshes before every request.
type simSNMP struct {
	community string
	refresh   func() map[string]gosnmp.SnmpPDU
	conn      net.PacketConn

	mu   sync.Mutex
	oids []string // sorted
	vals map[string]gosnmp.SnmpPDU
}

func startSimSNMP(ctx context.Context, community string, refresh func() map[string]gosnmp.SnmpPDU) (*simSNMP, error) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &simSNMP{community: community, refresh: refresh, conn: pc}
	go func() { <-ctx.Done(); pc.Close() }()
	go s.serve()
	return s, nil
}

func (s *simSNMP) Port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

func oidParts(o string) []int {
	ps := strings.Split(strings.Trim(o, "."), ".")
	out := make([]int, len(ps))
	for i, p := range ps {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

func oidLess(a, b string) bool {
	x, y := oidParts(a), oidParts(b)
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func (s *simSNMP) load() {
	vals := s.refresh()
	oids := make([]string, 0, len(vals))
	for k := range vals {
		oids = append(oids, k)
	}
	sort.Slice(oids, func(i, j int) bool { return oidLess(oids[i], oids[j]) })
	s.oids, s.vals = oids, vals
}

func (s *simSNMP) next(o string) (gosnmp.SnmpPDU, bool) {
	o = strings.TrimPrefix(o, ".")
	i := sort.Search(len(s.oids), func(i int) bool { return oidLess(o, s.oids[i]) })
	if i >= len(s.oids) {
		return gosnmp.SnmpPDU{Name: "." + o, Type: gosnmp.EndOfMibView}, false
	}
	return s.pdu(s.oids[i]), true
}

func (s *simSNMP) pdu(o string) gosnmp.SnmpPDU {
	p := s.vals[o]
	p.Name = "." + o
	return p
}

func (s *simSNMP) serve() {
	buf := make([]byte, 65535)
	dec := &gosnmp.GoSNMP{}
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := dec.SnmpDecodePacket(append([]byte(nil), buf[:n]...))
		if err != nil || req.Community != s.community || req.Version == gosnmp.Version3 {
			continue // wrong community: real agents stay silent
		}
		s.mu.Lock()
		s.load()
		resp := &gosnmp.SnmpPacket{Version: req.Version, Community: req.Community, PDUType: gosnmp.GetResponse, RequestID: req.RequestID}
		switch req.PDUType {
		case gosnmp.GetRequest:
			for _, v := range req.Variables {
				o := strings.TrimPrefix(v.Name, ".")
				if _, ok := s.vals[o]; ok {
					resp.Variables = append(resp.Variables, s.pdu(o))
				} else {
					resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchObject})
				}
			}
		case gosnmp.GetNextRequest:
			for _, v := range req.Variables {
				p, _ := s.next(v.Name)
				resp.Variables = append(resp.Variables, p)
			}
		case gosnmp.GetBulkRequest:
			reps := int(req.MaxRepetitions)
			if reps <= 0 || reps > 50 {
				reps = 50
			}
			for _, v := range req.Variables {
				cur := v.Name
				for range reps {
					p, ok := s.next(cur)
					resp.Variables = append(resp.Variables, p)
					if !ok {
						break
					}
					cur = p.Name
				}
			}
		}
		s.mu.Unlock()
		if out, err := resp.MarshalMsg(); err == nil {
			s.conn.WriteTo(out, addr)
		}
	}
}

// helpers to build PDUs
func pduStr(s string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte(s)}
}
func pduBytes(b []byte) gosnmp.SnmpPDU { return gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: b} }
func pduInt(n int) gosnmp.SnmpPDU      { return gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: n} }
func pduGauge(n uint) gosnmp.SnmpPDU   { return gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: n} }
func pduC32(n uint) gosnmp.SnmpPDU     { return gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: n} }
func pduC64(n uint64) gosnmp.SnmpPDU   { return gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: n} }
func pduTicks(n uint32) gosnmp.SnmpPDU { return gosnmp.SnmpPDU{Type: gosnmp.TimeTicks, Value: n} }
func pduIP(s string) gosnmp.SnmpPDU    { return gosnmp.SnmpPDU{Type: gosnmp.IPAddress, Value: s} }
func pduOID(s string) gosnmp.SnmpPDU   { return gosnmp.SnmpPDU{Type: gosnmp.ObjectIdentifier, Value: s} }

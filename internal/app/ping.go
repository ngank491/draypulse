package app

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ---------- ICMP ping from the DrayPulse host ----------
//
// Order of attempts: unprivileged ICMP socket (Linux ping_group_range, macOS,
// Docker), raw socket (root / CAP_NET_RAW, Windows admin), then the system
// "ping" command. The working method is remembered.

var pingMethod struct {
	sync.Mutex
	m string // "" | "udp" | "raw" | "exec"
}

func localPing(ctx context.Context, addr string, count int) (PingResult, error) {
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() == nil {
		return PingResult{}, errors.New("chỉ hỗ trợ ping IPv4")
	}
	pingMethod.Lock()
	m := pingMethod.m
	pingMethod.Unlock()
	try := []string{"udp", "raw", "exec"}
	if m != "" {
		try = []string{m}
	}
	var lastErr error
	for _, t := range try {
		var res PingResult
		var err error
		if t == "exec" {
			res, err = execPing(ctx, addr, count)
		} else {
			res, err = icmpPing(ctx, t, ip.To4(), count)
		}
		if err == nil {
			pingMethod.Lock()
			pingMethod.m = t
			pingMethod.Unlock()
			return res, nil
		}
		lastErr = err
	}
	return PingResult{}, lastErr
}

func icmpPing(ctx context.Context, kind string, ip net.IP, count int) (PingResult, error) {
	network := "udp4"
	if kind == "raw" {
		network = "ip4:icmp"
	}
	c, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		return PingResult{}, err
	}
	defer c.Close()
	res := PingResult{Sent: count, RTT: -1}
	id := rand.IntN(0xffff)
	var dst net.Addr = &net.IPAddr{IP: ip}
	if kind == "udp" {
		dst = &net.UDPAddr{IP: ip}
	}
	var sum float64
	buf := make([]byte, 1500)
	for seq := 1; seq <= count; seq++ {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("draypulse-ping")}}
		b, _ := msg.Marshal(nil)
		start := time.Now()
		if _, err := c.WriteTo(b, dst); err != nil {
			return res, err
		}
		deadline := start.Add(time.Second)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		c.SetReadDeadline(deadline)
		for {
			n, peer, err := c.ReadFrom(buf)
			if err != nil {
				break // timeout: lost
			}
			rm, err := icmp.ParseMessage(1, buf[:n])
			if err != nil || rm.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			echo, ok := rm.Body.(*icmp.Echo)
			if !ok || echo.Seq != seq || (kind == "raw" && echo.ID != id) {
				continue // unprivileged sockets rewrite the ID; the kernel filters for us
			}
			if pa := peerIP(peer); pa != nil && !pa.Equal(ip) {
				continue
			}
			res.Received++
			sum += float64(time.Since(start).Microseconds()) / 1000
			break
		}
		if seq < count {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if res.Received > 0 {
		res.RTT = sum / float64(res.Received)
	}
	return res, nil
}

func peerIP(a net.Addr) net.IP {
	switch t := a.(type) {
	case *net.IPAddr:
		return t.IP
	case *net.UDPAddr:
		return t.IP
	}
	return nil
}

var (
	reExecRecv = regexp.MustCompile(`(\d+)\s+(?:packets\s+)?received|Received = (\d+)`)
	reExecRTT  = regexp.MustCompile(`= [\d.]+/([\d.]+)/|Average = (\d+)ms`)
)

func execPing(ctx context.Context, addr string, count int) (PingResult, error) {
	var args []string
	if runtime.GOOS == "windows" {
		args = []string{"-n", strconv.Itoa(count), "-w", "1000", addr}
	} else {
		args = []string{"-n", "-c", strconv.Itoa(count), "-W", "1", "-i", "0.3", addr}
	}
	cmd := exec.CommandContext(ctx, "ping", args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	s := string(out)
	m := reExecRecv.FindStringSubmatch(s)
	if m == nil {
		if err != nil {
			return PingResult{}, errors.New("không chạy được ping trên máy DrayPulse: " + strings.TrimSpace(firstLine(s+" "+err.Error())))
		}
		return PingResult{}, errors.New("không đọc được kết quả ping")
	}
	res := PingResult{Sent: count, RTT: -1}
	res.Received, _ = strconv.Atoi(m[1] + m[2])
	if r := reExecRTT.FindStringSubmatch(s); r != nil {
		res.RTT, _ = strconv.ParseFloat(r[1]+r[2], 64)
	}
	return res, nil
}

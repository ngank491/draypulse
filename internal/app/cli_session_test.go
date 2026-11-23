package app

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fastCLITimers shortens the session timers for a test.
func fastCLITimers(t *testing.T, idle, busy time.Duration) {
	t.Helper()
	oi, ob, oe := cliIdle, cliBusyWait, cliExitWait
	cliIdle, cliBusyWait, cliExitWait = idle, busy, 500*time.Millisecond
	t.Cleanup(func() { cliIdle, cliBusyWait, cliExitWait = oi, ob, oe })
}

func simClient(sim *simCLI) *cliClient {
	return newCLIClient(CLIConfig{Proto: "telnet", Host: "127.0.0.1", Port: sim.Port(), User: "admin", Pass: "pw"})
}

func echoSim(t *testing.T) *simCLI {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sim, err := startSimCLI(ctx, "Vigor3912S", "admin", "pw", func(cmd string) string { return "ok " + cmd })
	if err != nil {
		t.Fatal(err)
	}
	return sim
}

// A full Vigor answers an SSH connection with a text banner instead of
// "SSH-2.0-…": that must read as "busy", not as a broken handshake.
func TestCLIBusyBannerSSH(t *testing.T) {
	fastCLITimers(t, time.Minute, 20*time.Millisecond)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Write([]byte(simBusyBanner))
			c.Close()
		}
	}()
	c := newCLIClient(CLIConfig{Proto: "ssh", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "admin", Pass: "pw"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Run(ctx, "sys version"); !errors.Is(err, errCLIBusy) {
		t.Fatalf("want errCLIBusy, got %v", err)
	}
	if n.Load() != 3 {
		t.Fatalf("want 3 attempts (2 retries), got %d", n.Load())
	}
}

func TestCLIBusyWaitsForFreedSlot(t *testing.T) {
	fastCLITimers(t, time.Minute, 100*time.Millisecond)
	sim := echoSim(t)
	sim.MaxSessions, sim.ReleaseDelay = 1, 150*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, b := simClient(sim), simClient(sim)
	if _, err := a.Run(ctx, "sys version"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Run(ctx, "sys version"); !errors.Is(err, errCLIBusy) {
		t.Fatalf("second client while the only slot is held: want errCLIBusy, got %v", err)
	}
	a.Close() // logs out; the router frees the slot 150 ms later
	out, err := b.Run(ctx, "sys version")
	if err != nil || out["sys version"] != "ok sys version" {
		t.Fatalf("after the slot is freed: %q %v", out, err)
	}
}

// DrayPulse logs out an idle session before the router drops it, and the
// next command still works although the router frees slots late.
func TestCLILogsOutWhenIdle(t *testing.T) {
	fastCLITimers(t, 150*time.Millisecond, 100*time.Millisecond)
	sim := echoSim(t)
	sim.MaxSessions, sim.IdleTimeout, sim.ReleaseDelay = 1, 2*time.Second, 150*time.Millisecond
	c := simClient(sim)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := range 3 {
		if _, err := c.Run(ctx, "sys version"); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if got := sim.logins.Load(); got != 3 {
		t.Fatalf("each idle gap must end with a logout and a new login, got %d logins", got)
	}
	// within the idle limit the session is reused
	c.Run(ctx, "sys version")
	c.Run(ctx, "sys version")
	if got := sim.logins.Load(); got != 4 {
		t.Fatalf("busy session must be reused, got %d logins", got)
	}
	c.Close()
}

// The router drops the idle session first (Vigor 3912S after ~16–20 s): the
// command is retried on a new session once the slot is free.
func TestCLIRouterDroppedSession(t *testing.T) {
	fastCLITimers(t, time.Minute, 150*time.Millisecond)
	old := cliSettle
	cliSettle = 20 * time.Millisecond // shorter than the simulated idle drop
	t.Cleanup(func() { cliSettle = old })
	sim := echoSim(t)
	sim.MaxSessions, sim.IdleTimeout, sim.ReleaseDelay = 1, 150*time.Millisecond, 350*time.Millisecond
	c := simClient(sim)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Run(ctx, "sys version"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond) // dropped at ~150 ms, slot free again at ~500 ms
	out, err := c.Run(ctx, "show lan")
	if err != nil || out["show lan"] != "ok show lan" {
		t.Fatalf("%q %v", out, err)
	}
	if sim.busy.Load() == 0 {
		t.Fatal("the test should have hit the busy router at least once")
	}
}

// A failing CLI must not empty ARP/DHCP: the poller keeps the previous rows
// only for real errors, errNotSupported replaces them.
func TestFetchCLIErrorIsNotUnsupported(t *testing.T) {
	fastCLITimers(t, time.Minute, 10*time.Millisecond)
	sim := echoSim(t)
	sim.MaxSessions = 1
	holder := simClient(sim)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := holder.Run(ctx, "sys version"); err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	d := newDraytekSource("127.0.0.1", DrayOpts{SNMPVersion: "off", CLI: "telnet", CLIPort: sim.Port()}, SNMPSecrets{}, "admin", "pw")
	defer d.Close()
	for _, p := range []string{"/ip/arp", "/ip/dhcp-server/lease", "/draytek/vlan", "/draytek/lan", "/interface/bridge/host"} {
		if _, err := d.Fetch(ctx, p, nil); err == nil || errors.Is(err, errNotSupported) {
			t.Errorf("%s: want a real error while the router is busy, got %v", p, err)
		}
	}
	noCLI := newDraytekSource("127.0.0.1", DrayOpts{SNMPVersion: "off"}, SNMPSecrets{}, "", "")
	if _, err := noCLI.Fetch(ctx, "/ip/dhcp-server/lease", nil); !errors.Is(err, errNotSupported) {
		t.Fatalf("without CLI: want errNotSupported, got %v", err)
	}
}

// A router pinging many devices keeps the CLI busy all the time: a blocking
// transaction must get the session after the current command, not after the
// whole queue.
func TestUrgentLockJumpsQueue(t *testing.T) {
	fastCLITimers(t, time.Minute, 50*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sim, err := startSimCLI(ctx, "Vigor3912S", "admin", "pw", func(cmd string) string {
		time.Sleep(100 * time.Millisecond) // a slow command, like "ip ping"
		return "ok"
	})
	if err != nil {
		t.Fatal(err)
	}
	c := simClient(sim)
	defer c.Close()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 6 { // queued pings
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c.Run(ctx, "ip ping 192.168.1.10 AUTO")
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	t0 := time.Now()
	c.lockUrgent()
	waited := time.Since(t0)
	c.mu.Unlock()
	close(stop)
	wg.Wait()
	if waited > 350*time.Millisecond { // one command (+ slack), not six
		t.Fatalf("blocking transaction waited %v behind routine commands", waited)
	}
}

// DrayOS prints a second prompt after an SSH login. Read as the answer to the
// first command, it shifted every later answer by one (WAN pings empty, the
// ARP table read as DHCP leases).
func TestCLINoShiftAfterExtraPrompt(t *testing.T) {
	for _, settle := range []time.Duration{cliSettle, time.Millisecond} { // the drain, then the echo guard alone
		t.Run(settle.String(), func(t *testing.T) {
			old := cliSettle
			cliSettle = settle
			t.Cleanup(func() { cliSettle = old })
			fastCLITimers(t, time.Minute, 50*time.Millisecond)
			sim := echoSim(t)
			sim.ExtraPrompt = true
			c := simClient(sim)
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			out, err := c.Run(ctx, "ip ping 8.8.8.8 WAN1", "sys version", "ip arp status")
			if err != nil {
				t.Fatal(err)
			}
			for _, cmd := range []string{"ip ping 8.8.8.8 WAN1", "sys version", "ip arp status"} {
				if out[cmd] != "ok "+cmd {
					t.Fatalf("%q got %q (answers shifted)", cmd, out[cmd])
				}
			}
			o2, err := c.Run(ctx, "srv dhcp status")
			if err != nil || o2["srv dhcp status"] != "ok srv dhcp status" {
				t.Fatalf("next call: %q %v", o2, err)
			}
		})
	}
}

// Audit and "Kiểm tra kết nối" borrow the poller's session: Vigor routers
// accept one Telnet/SSH session only.
func TestSharedCLI(t *testing.T) {
	bm := &simBindMAC{}
	h, r, _ := blockHarness(t, bm)
	rs := h.get(r.ID)
	running := newDraytekSource("127.0.0.1", r.Opts, SNMPSecrets{}, "admin", "pw")
	defer running.Close()
	rs.mu.Lock()
	rs.src = running
	rs.mu.Unlock()
	defer func() { rs.mu.Lock(); rs.src = nil; rs.mu.Unlock() }()

	same := newDraytekSource("127.0.0.1", r.Opts, SNMPSecrets{}, "admin", "pw")
	own := same.cli
	restore := h.sharedCLI(r.ID, same)
	if same.cli != running.cli {
		t.Fatal("same router and login: the running session must be lent")
	}
	restore()
	if same.cli != own {
		t.Fatal("restore must give the own client back")
	}
	other := newDraytekSource("127.0.0.1", r.Opts, SNMPSecrets{}, "admin", "new-password")
	restore = h.sharedCLI(r.ID, other)
	if other.cli == running.cli {
		t.Fatal("a changed login must not use the running session")
	}
	restore()
}

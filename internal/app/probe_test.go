package app

import "testing"

// Vigor2926 plus (DrayOS 4.4.3_Vietfpt) prints Linux-style ping output; it
// was read as "1 sent, 0 received", so WAN1 showed "Mất Internet" for days.
func TestParseRouterPingLinuxStyle(t *testing.T) {
	out := "\nPinging 8.8.8.8 with 64 bytes of Data through WAN1:\n\n" +
		"64 bytes from 8.8.8.8: seq=1 time=34.95ms\n64 bytes from 8.8.8.8: seq=2 time=34.77ms\n64 bytes from 8.8.8.8: seq=3 time=34.64ms\n" +
		"32 bytes from 8.8.8.8: seq=256 time=0.09ms\n32 bytes from 8.8.8.8: seq=256 time=0.08ms\n\n" +
		"5 packets transmitted, 5 received, 0% packet loss, time 4950ms\nrtt min/avg/max/mdev = 0.88/20.910/34.950/17.0 ms"
	p, ok := parseRouterPing(out)
	if !ok || p.Sent != 5 || p.Received != 3 || p.RTT < 34 || p.RTT > 35.5 {
		t.Fatalf("%+v %v", p, ok)
	}
	lost := "\nPinging 8.8.8.8 with 64 bytes of Data through WAN1:\n\nRequest timed out.\nRequest timed out.\n\n5 packets transmitted, 0 received, 100% packet loss, time 5000ms"
	if p, ok := parseRouterPing(lost); !ok || p.Sent != 5 || p.Received != 0 || p.RTT != -1 {
		t.Fatalf("lost: %+v %v", p, ok)
	}
}

// A WAN ping through the router that keeps failing to run (CLI busy, empty
// answer) must not leave the line "down" for days: after three such checks
// the state is "error", and a later success reports the recovery if the
// outage was reported.
func TestProbeErrorsDoNotKeepDown(t *testing.T) {
	p := newProbe()
	p.step(false, false, 1, -1, 2)
	if p.step(false, false, 2, -1, 2) != "down" {
		t.Fatal("two failed pings must mark the line down")
	}
	p.Alerted = true
	for i := int64(3); i <= 4; i++ {
		p.step(false, true, i, -1, 2)
		if p.Status != "down" {
			t.Fatalf("one or two errors keep the last state, got %s", p.Status)
		}
	}
	p.step(false, true, 5, -1, 2)
	if p.Status != "error" || p.Since != 5 || p.Errs != 3 {
		t.Fatalf("after three errors: %+v", p)
	}
	if tr := p.step(true, false, 6, 20, 2); tr != "up" || p.Status != "up" || p.Errs != 0 {
		t.Fatalf("recovery of a reported outage must be announced: %q %+v", tr, p)
	}
	// errors on a line that was up never raise an alert
	q := newProbe()
	q.step(true, false, 1, 5, 2)
	for i := int64(2); i <= 5; i++ {
		if tr := q.step(false, true, i, -1, 2); tr != "" {
			t.Fatalf("errors must not alert, got %q", tr)
		}
	}
	if tr := q.step(true, false, 6, 5, 2); tr != "" || q.Status != "up" {
		t.Fatalf("back from error without an outage: %q %+v", tr, q)
	}
}

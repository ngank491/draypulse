package app

import "testing"

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

package app

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// simBindMAC imitates DrayOS "ip bindmac" for the demo router and the tests.
type simBindMAC struct {
	mu      sync.Mutex
	on      bool
	strict  bool
	entries []bindEntry
	// IgnoreAdd makes "add" print OK but store nothing (firmware quirk test).
	IgnoreAdd bool
	// EntriesOnly: "show" prints only the entries, no ON/OFF lines.
	EntriesOnly bool
	// Silent: "show" prints nothing at all.
	Silent bool
	Log    []string
}

var reSimBind = regexp.MustCompile(`^ip bindmac (show|on|off|add (\S+) (\S+) (.*)|del (\S+))$`)

func (b *simBindMAC) handle(cmd string) (string, bool) {
	m := reSimBind.FindStringSubmatch(cmd)
	if m == nil {
		return "", false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case m[1] == "show":
		var s strings.Builder
		if b.Silent {
			return "", true
		}
		if !b.EntriesOnly {
			fmt.Fprintf(&s, "ip bind mac function is turned %s\nip bind mac function is STRICT %s\nShow all IP Bind MAC entries.\n",
				map[bool]string{true: "ON", false: "OFF"}[b.on], map[bool]string{true: "ON", false: "OFF"}[b.strict])
		}
		for _, e := range b.entries {
			fmt.Fprintf(&s, "IP : %s bind MAC : %s HOST ID :              \nComment : %s\n", e.IP, strings.ToLower(strings.ReplaceAll(e.MAC, ":", "-")), e.Comment)
		}
		return s.String(), true
	case m[1] == "on" || m[1] == "off":
		b.on = m[1] == "on"
		b.Log = append(b.Log, cmd)
		return "", true
	case m[2] != "":
		b.Log = append(b.Log, cmd)
		if !b.IgnoreAdd {
			b.entries = append(b.entries, bindEntry{IP: m[2], MAC: strings.ToUpper(m[3]), Comment: strings.Fields(m[4] + " ")[0]})
		}
		return "", true
	default:
		b.Log = append(b.Log, cmd)
		for i, e := range b.entries {
			if e.IP == m[5] {
				b.entries = append(b.entries[:i], b.entries[i+1:]...)
				break
			}
		}
		return "", true
	}
}

package app

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync/atomic"
)

// simCLI is a tiny DrayOS-like Telnet server used by the demo router and the
// tests: "Account:"/"Password:" login, "<name>> " prompt, echoed input and the
// "--- MORE ---" pager after 20 lines.
type simCLI struct {
	ln         net.Listener
	name       string
	user, pass string
	handler    func(cmd string) string
	logins     atomic.Int32
}

func startSimCLI(ctx context.Context, name, user, pass string, handler func(string) string) (*simCLI, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &simCLI{ln: ln, name: name, user: user, pass: pass, handler: handler}
	go func() { <-ctx.Done(); ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s, nil
}

func (s *simCLI) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

const simMore = "--- MORE ---   ['q': Quit, 'Enter': New Lines, 'Space Bar': Next Page] ---"

func (s *simCLI) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := func(x string) { c.Write([]byte(x)) }
	readLine := func() (string, bool) {
		var b strings.Builder
		for {
			ch, err := r.ReadByte()
			if err != nil {
				return "", false
			}
			if ch == 255 { // IAC: skip the 2-byte option reply
				r.ReadByte()
				r.ReadByte()
				continue
			}
			if ch == '\n' {
				return strings.TrimRight(b.String(), "\r"), true
			}
			b.WriteByte(ch)
		}
	}
	w("\xff\xfb\x01\xff\xfb\x03") // WILL ECHO, WILL SGA
	for tries := 0; ; tries++ {
		w("Account:")
		u, ok := readLine()
		if !ok {
			return
		}
		w("\r\nPassword: ")
		p, ok := readLine()
		if !ok {
			return
		}
		if u == s.user && p == s.pass {
			break
		}
		if tries >= 2 {
			w("\r\nLogin fail, too many retries\r\n")
			return
		}
		w("\r\nLogin fail\r\n")
	}
	s.logins.Add(1)
	w("\r\n\r\nType ? for command help\r\n\r\n" + s.name + "> ")
	for {
		cmd, ok := readLine()
		if !ok {
			return
		}
		cmd = strings.TrimSpace(cmd)
		w(cmd + "\r\n")
		if cmd == "exit" || cmd == "quit" {
			return
		}
		out := ""
		if cmd != "" {
			out = s.handler(cmd)
		}
		lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
		for i, l := range lines {
			if i > 0 && i%20 == 0 {
				w(simMore)
				ch, err := r.ReadByte()
				if err != nil {
					return
				}
				w("\r" + strings.Repeat(" ", len(simMore)) + "\r")
				if ch == 'q' {
					break
				}
			}
			w(l + "\r\n")
		}
		w(s.name + "> ")
	}
}

package app

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------- DrayTek CLI over Telnet or SSH (read-only commands only) ----------

// CLIConfig describes how to reach the DrayOS command line.
type CLIConfig struct {
	Proto string // "telnet" | "ssh"
	Host  string
	Port  int
	User  string
	Pass  string
}

// cliAllowed is the exact list of commands DrayPulse may ever send. Each one
// only displays information. Prefix matching is deliberately not used: many
// DrayOS commands change settings when given arguments (e.g. "sys name X").
var cliAllowed = map[string]bool{
	"sys version": true, "sys iface": true, "show status": true, "show lan": true, "show statistic": true,
	"wan status": true, "ip arp status": true, "ip dhcpc status": true, "ip route status": true,
	"srv dhcp status": true, "mngt rmtcfg status": true, "sys syslog status": true, "vlan status": true,
	"show session": true, "ip session status": true, "ip session show": true, "ip dataflowmonitor status": true,
}

var reCLIPing = regexp.MustCompile(`^ip ping \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} (AUTO|WAN\d{1,2})$`)

func cliCommandAllowed(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	return cliAllowed[cmd] || reCLIPing.MatchString(cmd)
}

// cliWriteAllowed are the only configuration changes DrayPulse can make, used
// by client blocking: adding/removing its own Bind IP to MAC entries (always
// the fixed blocking MAC and the comment "DrayPulse") and switching the
// function on/off. "del all" and strict mode are not possible.
var cliWriteAllowed = []*regexp.Regexp{
	regexp.MustCompile(`^ip bindmac show$`),
	regexp.MustCompile(`^ip bindmac (on|off)$`),
	regexp.MustCompile(`^ip bindmac add \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} 02:dd:00:00:00:01 DrayPulse$`),
	regexp.MustCompile(`^ip bindmac del \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`),
}

func cliWriteCommandAllowed(cmd string) bool {
	if cliCommandAllowed(cmd) {
		return true
	}
	for _, re := range cliWriteAllowed {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

var moreRe = regexp.MustCompile(`(?i)-+\s*more\s*-+.*$|--More--\s*$|press any key.*$`)
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]`)

type cliClient struct {
	cfg CLIConfig
	mu  sync.Mutex // one session at a time per router; DrayOS allows few CLI users
	cc  *cliConn
}

func newCLIClient(cfg CLIConfig) *cliClient {
	if cfg.Port == 0 {
		if cfg.Proto == "ssh" {
			cfg.Port = 22
		} else {
			cfg.Port = 23
		}
	}
	return &cliClient{cfg: cfg}
}

// cliConn is the byte stream of an interactive CLI session.
type cliConn struct {
	raw     net.Conn
	prompt  *regexp.Regexp // learned at login
	lastUse time.Time
	rw      io.ReadWriter
	closeFn func()
	buf     bytes.Buffer
	readCh  chan []byte
	errCh   chan error
	telnet  bool
	matched string // text matched by the last expect
}

// learnPrompt turns the prompt seen after login ("Vigor2927> ") into an exact
// pattern, so command output containing ">" cannot end a read early.
func (cc *cliConn) learnPrompt() *regexp.Regexp {
	name := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(cc.matched), ">"))
	return regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `>\s*$`)
}

// errCLIBusy: every Telnet/SSH slot of the router is taken. DrayOS then prints
// "No connection is available now. Try again later!" instead of a login (or an
// SSH version line) and hangs up.
var errCLIBusy = errors.New("router đã hết phiên Telnet/SSH (“No connection is available now”) – phiên cũ chưa được router giải phóng, thử lại sau")

var reCLIBusy = regexp.MustCompile(`(?i)no connection is available`)

// peekConn replays bytes read ahead from a connection.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// sshBusyCheck reads the first bytes of an SSH connection: a server with a
// free slot starts with "SSH-", a full DrayOS prints its busy banner.
func sshBusyCheck(conn net.Conn) (net.Conn, error) {
	br := bufio.NewReader(conn)
	head, err := br.Peek(4)
	if err == nil && string(head) == "SSH-" {
		return peekConn{conn, br}, nil
	}
	more, _ := br.Peek(br.Buffered())
	if br.Buffered() < 80 {
		more, _ = br.Peek(80) // the banner is short and followed by a hang-up
	}
	if reCLIBusy.Match(more) || reCLIBusy.Match(head) {
		return nil, errCLIBusy
	}
	if err != nil {
		return nil, fmt.Errorf("SSH: router không gửi lời chào SSH (%v)", err)
	}
	return peekConn{conn, br}, nil
}

func (c *cliClient) dial(ctx context.Context) (*cliConn, error) {
	addr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.Port))
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, friendlyCLIErr(err)
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if c.cfg.Proto == "ssh" {
		pc, err := sshBusyCheck(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = pc
	}
	if c.cfg.Proto != "ssh" {
		cc := &cliConn{raw: conn, rw: conn, closeFn: func() { conn.Close() }, telnet: true}
		cc.startReader()
		return cc, nil
	}
	cfg := &ssh.ClientConfig{
		User: c.cfg.User,
		Auth: []ssh.AuthMethod{ssh.Password(c.cfg.Pass), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range qs {
				ans[i] = c.cfg.Pass
			}
			return ans, nil
		})},
		// DrayTek devices ship self-generated host keys; there is no PKI to verify against.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	}
	// Older DrayOS builds only offer legacy algorithms; allow them (read-only use).
	cfg.KeyExchanges = []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
		"diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha256"}
	cfg.Ciphers = []string{"aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc"}
	cfg.HostKeyAlgorithms = []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, errors.New("SSH: sai user hoặc mật khẩu router")
		}
		return nil, fmt.Errorf("SSH: %v", err)
	}
	client := ssh.NewClient(sc, chans, reqs)
	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("SSH: %v", err)
	}
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	sess.RequestPty("vt100", 200, 512, ssh.TerminalModes{ssh.ECHO: 0})
	if err := sess.Shell(); err != nil {
		client.Close()
		return nil, fmt.Errorf("SSH shell: %v", err)
	}
	cc := &cliConn{raw: conn, rw: struct {
		io.Reader
		io.Writer
	}{out, in}, closeFn: func() { sess.Close(); client.Close() }}
	cc.startReader()
	return cc, nil
}

func friendlyCLIErr(err error) error {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return errors.New("CLI router không phản hồi (timeout)")
	case strings.Contains(err.Error(), "connection refused"):
		return errors.New("router từ chối Telnet/SSH (dịch vụ chưa bật hoặc sai cổng, xem System Maintenance → Management)")
	case strings.Contains(err.Error(), "no route to host"), strings.Contains(err.Error(), "network is unreachable"):
		return errors.New("không có đường tới router")
	}
	return err
}

func (cc *cliConn) startReader() {
	cc.readCh, cc.errCh = make(chan []byte, 64), make(chan error, 1)
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := cc.rw.Read(b)
			if n > 0 {
				cc.readCh <- append([]byte(nil), b[:n]...)
			}
			if err != nil {
				cc.errCh <- err
				close(cc.readCh)
				return
			}
		}
	}()
}

func (cc *cliConn) close() { cc.closeFn() }

// shutdown logs out and waits (briefly) until the router hangs up. DrayOS
// frees the CLI slot only when its side of the session ends; dropping the
// connection without waiting leaves half-closed sessions that fill all slots.
func (cc *cliConn) shutdown() {
	cc.raw.SetDeadline(time.Now().Add(cliExitWait + time.Second))
	cc.write("exit\r\n")
	t := time.NewTimer(cliExitWait)
	defer t.Stop()
	for {
		select {
		case _, ok := <-cc.readCh:
			if ok {
				continue
			}
		case <-t.C:
		}
		cc.close()
		return
	}
}

func (cc *cliConn) write(s string) error {
	_, err := cc.rw.Write([]byte(s))
	return err
}

// telnetFilter strips IAC sequences and answers option negotiation:
// we refuse everything except the server echoing / suppress-go-ahead.
func (cc *cliConn) telnetFilter(b []byte) []byte {
	const iac, will, wont, do, dont, sb, se = 255, 251, 252, 253, 254, 250, 240
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != iac {
			out = append(out, b[i])
			continue
		}
		if i+1 >= len(b) {
			break
		}
		switch cmd := b[i+1]; cmd {
		case iac:
			out = append(out, iac)
			i++
		case will, wont, do, dont:
			if i+2 >= len(b) {
				i = len(b)
				break
			}
			opt := b[i+2]
			var reply byte
			switch cmd {
			case will:
				reply = dont
				if opt == 1 || opt == 3 { // ECHO, SGA
					reply = do
				}
			case do:
				reply = wont
				if opt == 3 {
					reply = will
				}
			}
			if reply != 0 {
				cc.rw.Write([]byte{iac, reply, opt})
			}
			i += 2
		case sb:
			j := i + 2
			for j+1 < len(b) && !(b[j] == iac && b[j+1] == se) {
				j++
			}
			i = j + 1
		default:
			i++
		}
	}
	return out
}

// expect reads until one of the patterns matches the accumulated buffer.
// It returns the index of the pattern and the text before the match.
func (cc *cliConn) expect(ctx context.Context, timeout time.Duration, pats ...*regexp.Regexp) (int, string, error) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		text := cleanCLI(cc.buf.String())
		for i, p := range pats {
			if loc := p.FindStringIndex(text); loc != nil {
				cc.buf.Reset()
				cc.matched = text[loc[0]:loc[1]]
				return i, text[:loc[0]], nil
			}
		}
		if moreRe.MatchString(text) { // pager: ask for the next page and keep the text
			cc.buf.Reset()
			cc.buf.WriteString(moreRe.ReplaceAllString(text, ""))
			cc.write(" ")
			continue
		}
		if cc.buf.Len() > 4<<20 {
			return -1, "", errors.New("CLI trả về quá nhiều dữ liệu")
		}
		select {
		case <-ctx.Done():
			return -1, "", errors.New("CLI router không phản hồi (timeout)")
		case <-t.C:
			return -1, text, errors.New("CLI router không phản hồi (timeout)")
		case b, ok := <-cc.readCh:
			if !ok {
				err := <-cc.errCh
				if err == io.EOF {
					err = errors.New("router đóng phiên CLI")
				}
				return -1, text, err
			}
			if cc.telnet {
				b = cc.telnetFilter(b)
			}
			cc.buf.Write(b)
		}
	}
}

func cleanCLI(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	// a lone \r is used to redraw lines: keep the last version of the line
	var b strings.Builder
	for i, line := range strings.Split(s, "\n") {
		if i > 0 {
			b.WriteByte('\n')
		}
		if k := strings.LastIndex(strings.TrimRight(line, "\r"), "\r"); k >= 0 {
			line = line[k+1:]
		}
		b.WriteString(strings.TrimRight(line, "\r"))
	}
	return strings.Map(func(r rune) rune {
		if r == '\b' || r == 0 {
			return -1
		}
		return r
	}, b.String())
}

var (
	reLoginUser = regexp.MustCompile(`(?i)(account|login|user ?name)\s*:\s*$`)
	reLoginPass = regexp.MustCompile(`(?i)password\s*:\s*$`)
	reLoginFail = regexp.MustCompile(`(?i)(fail|incorrect|invalid|denied|locked|too many)`)
	// DrayOS prompt: "DrayTek> ", "Vigor2927>  ", or a bare "> " on some builds
	rePromptEnd = regexp.MustCompile(`(?m)^\s*[\w.\-]{0,64}>\s*$`)
)

// login drives the Telnet (or SSH-shell) login dialog up to the first prompt.
func (cc *cliConn) login(ctx context.Context, user, pass string, proto string) error {
	if proto == "ssh" {
		// Already authenticated: some builds still print a banner and wait.
		cc.write("\r\n")
		_, _, err := cc.expect(ctx, 10*time.Second, rePromptEnd)
		if err == nil {
			cc.prompt = cc.learnPrompt()
		}
		return err
	}
	sentUser, sentPass := false, false
	for range 6 {
		i, text, err := cc.expect(ctx, 10*time.Second, reLoginUser, reLoginPass, rePromptEnd)
		if err != nil {
			if reCLIBusy.MatchString(text) {
				return errCLIBusy
			}
			return err
		}
		switch i {
		case 0:
			if sentUser && reLoginFail.MatchString(text) {
				return errors.New("Telnet: sai user hoặc mật khẩu router")
			}
			if sentPass {
				return errors.New("Telnet: sai user hoặc mật khẩu router")
			}
			cc.write(user + "\r\n")
			sentUser = true
		case 1:
			if sentPass {
				return errors.New("Telnet: sai user hoặc mật khẩu router")
			}
			cc.write(pass + "\r\n")
			sentPass = true
		case 2:
			if sentPass && reLoginFail.MatchString(text) && !strings.Contains(strings.ToLower(text), "last login") {
				return errors.New("Telnet: đăng nhập bị từ chối: " + firstLine(text))
			}
			cc.prompt = cc.learnPrompt()
			return nil
		}
	}
	return errors.New("Telnet: không qua được bước đăng nhập")
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// Run executes read-only commands and returns each output. The session is
// kept open while it is in use (DrayOS logs every login), closed cleanly once
// idle, and re-opened on error.
func (c *cliClient) Run(ctx context.Context, cmds ...string) (map[string]string, error) {
	for _, cmd := range cmds {
		if !cliCommandAllowed(cmd) {
			return nil, fmt.Errorf("lệnh CLI không nằm trong danh sách chỉ-đọc: %q", cmd)
		}
	}
	return c.run(ctx, cmds)
}

// RunWrite also allows the fixed configuration commands of MAC blocking.
func (c *cliClient) RunWrite(ctx context.Context, cmds ...string) (map[string]string, error) {
	for _, cmd := range cmds {
		if !cliWriteCommandAllowed(cmd) {
			return nil, fmt.Errorf("lệnh CLI không được phép: %q", cmd)
		}
	}
	return c.run(ctx, cmds)
}

func (c *cliClient) run(ctx context.Context, cmds []string) (map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc != nil && time.Since(c.cc.lastUse) > cliIdle {
		c.closeLocked() // log out before the router drops the idle session itself
	}
	reused := c.cc != nil
	out, err := c.runLocked(ctx, cmds)
	if err != nil && reused && ctx.Err() == nil {
		c.closeLocked() // stale session (router timed it out): retry once
		out, err = c.runLocked(ctx, cmds)
	}
	if err != nil {
		c.closeLocked()
	}
	return out, err
}

// cliIdle is how long an unused session is kept. Vigor 3912S/2926 drop an
// idle SSH session after about 16–20 s and free its slot a moment later, so
// DrayPulse logs out well before that instead of reusing a dead session.
var cliIdle = 10 * time.Second

// cliExitWait bounds the wait for the router to hang up after "exit".
var cliExitWait = 2 * time.Second

// cliBusyWait is the pause before trying again when all CLI slots are taken
// (a session that just ended is freed by DrayOS within about a second).
var cliBusyWait = 1500 * time.Millisecond

func (c *cliClient) runLocked(ctx context.Context, cmds []string) (map[string]string, error) {
	if c.cc == nil {
		cc, err := c.open(ctx)
		if err != nil {
			return nil, err
		}
		c.cc = cc
	}
	cc := c.cc
	out := map[string]string{}
	for _, cmd := range cmds {
		wait := 15 * time.Second
		if strings.HasPrefix(cmd, "ip ping") || strings.HasPrefix(cmd, "ping") {
			wait = 25 * time.Second
		}
		cc.raw.SetDeadline(time.Now().Add(wait + 5*time.Second))
		cc.buf.Reset()
		if err := cc.write(cmd + "\r\n"); err != nil {
			return out, err
		}
		_, text, err := cc.expect(ctx, wait, cc.prompt)
		if err != nil {
			return out, err
		}
		out[cmd] = stripEcho(text, cmd)
	}
	cc.lastUse = time.Now()
	return out, nil
}

// Close ends the kept session, if any.
func (c *cliClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

func (c *cliClient) closeLocked() {
	if c.cc != nil {
		c.cc.shutdown()
		c.cc = nil
	}
}

// open dials and logs in. When the router has no free slot, it waits a
// little and tries again (twice), as the slot of a session that just ended
// is released shortly after.
func (c *cliClient) open(ctx context.Context) (*cliConn, error) {
	for attempt := 0; ; attempt++ {
		cc, err := c.dial(ctx)
		if err == nil {
			if err = cc.login(ctx, c.cfg.User, c.cfg.Pass, c.cfg.Proto); err == nil {
				return cc, nil
			}
			cc.close()
		}
		if !errors.Is(err, errCLIBusy) || attempt >= 2 {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(cliBusyWait * time.Duration(attempt+1)):
		}
	}
}

// stripEcho removes the echoed command line from the start of the output.
func stripEcho(text, cmd string) string {
	text = strings.TrimLeft(text, "\n ")
	if i := strings.Index(text, "\n"); i >= 0 && strings.Contains(text[:i], strings.TrimSpace(cmd)) {
		text = text[i+1:]
	} else if strings.TrimSpace(text) == strings.TrimSpace(cmd) {
		text = ""
	}
	return strings.TrimRight(text, "\n ")
}

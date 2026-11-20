package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var Version = "dev"

// setupCodeFile holds the first-run code for hosts where the log is hard to read.
const setupCodeFile = "setup-code.txt"

type Config struct {
	DataDir       string
	Listen        string
	TLS           string // "" | "auto" | "files"
	TLSCert       string
	TLSKey        string
	AdminUser     string
	AdminPassword string
	TrustProxy    bool
	CookieSecure  bool
	Demo          bool
	Syslog        string // UDP address for router syslog, "" = off
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	v := strings.ToLower(os.Getenv(key))
	return v == "1" || v == "true" || v == "yes"
}

func parseConfig(args []string) (*Config, error) {
	c := &Config{}
	fs := flag.NewFlagSet("draypulse", flag.ContinueOnError)
	fs.StringVar(&c.DataDir, "data", env("DRAYPULSE_DATA", "data"), "thư mục dữ liệu")
	fs.StringVar(&c.Listen, "listen", env("DRAYPULSE_LISTEN", ":8080"), "địa chỉ lắng nghe")
	fs.StringVar(&c.TLS, "tls", env("DRAYPULSE_TLS", ""), `HTTPS: "auto" (tự ký) hoặc để trống`)
	fs.StringVar(&c.TLSCert, "tls-cert", env("DRAYPULSE_TLS_CERT", ""), "file chứng chỉ PEM (tuỳ chọn)")
	fs.StringVar(&c.TLSKey, "tls-key", env("DRAYPULSE_TLS_KEY", ""), "file khoá PEM (tuỳ chọn)")
	fs.BoolVar(&c.TrustProxy, "trust-proxy", envBool("DRAYPULSE_TRUST_PROXY"), "tin header X-Forwarded-* từ reverse proxy")
	fs.BoolVar(&c.CookieSecure, "cookie-secure", envBool("DRAYPULSE_COOKIE_SECURE"), "luôn đặt cookie Secure")
	fs.BoolVar(&c.Demo, "demo", envBool("DRAYPULSE_DEMO"), "tạo router mô phỏng để dùng thử")
	fs.StringVar(&c.Syslog, "syslog", env("DRAYPULSE_SYSLOG", ":5514"), `nhận syslog từ router (UDP), "off" để tắt`)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	c.AdminUser = env("DRAYPULSE_ADMIN_USER", "admin")
	c.AdminPassword = os.Getenv("DRAYPULSE_ADMIN_PASSWORD")

	// Home Assistant add-on options (written by the Supervisor).
	var opts struct {
		AdminPassword string `json:"admin_password"`
		TLS           bool   `json:"https"`
		TrustProxy    bool   `json:"trust_proxy"`
	}
	if b, err := os.ReadFile(filepath.Join(c.DataDir, "options.json")); err == nil && json.Unmarshal(b, &opts) == nil {
		if opts.AdminPassword != "" {
			c.AdminPassword = opts.AdminPassword
		}
		if opts.TLS {
			c.TLS = "auto"
		}
		c.TrustProxy = c.TrustProxy || opts.TrustProxy
	}
	if c.TLSCert != "" || c.TLSKey != "" {
		c.TLS = "files"
	}
	if c.TLS != "" && c.TLS != "auto" && c.TLS != "files" {
		return nil, fmt.Errorf(`-tls chỉ nhận "auto"`)
	}
	return c, nil
}

func Main(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "version", "-version", "--version":
			fmt.Println("DrayPulse", Version)
			return nil
		case "reset-password":
			return resetPassword(args[1:])
		case "healthcheck":
			return healthcheck()
		}
	}
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Run(ctx, cfg)
}

// healthcheck is used by Docker (the scratch image has no curl).
func healthcheck() error {
	_, port, err := net.SplitHostPort(env("DRAYPULSE_LISTEN", ":8080"))
	if err != nil {
		return err
	}
	scheme := "http"
	if env("DRAYPULSE_TLS", "") != "" {
		scheme = "https"
	}
	c := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := c.Get(scheme + "://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("healthz %d", resp.StatusCode)
	}
	return nil
}

// resetPassword: draypulse reset-password [-data dir] <username> <new password>
func resetPassword(args []string) error {
	fs := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	dir := fs.String("data", env("DRAYPULSE_DATA", "data"), "thư mục dữ liệu")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("cách dùng: draypulse reset-password [-data DIR] <tên> <mật khẩu mới>")
	}
	if err := validPassword(fs.Arg(1)); err != nil {
		return err
	}
	dbPath := filepath.Join(*dir, "draypulse.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("không thấy %s – kiểm tra tham số -data", dbPath)
	}
	st, err := OpenStore(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	u, err := st.UserByName(fs.Arg(0))
	if errors.Is(err, ErrNotFound) {
		if _, err := st.CreateUser(fs.Arg(0), hashPassword(fs.Arg(1)), "admin"); err != nil {
			return err
		}
		fmt.Println("Đã tạo tài khoản quản trị", fs.Arg(0))
		return nil
	}
	if err != nil {
		return err
	}
	if err := st.SetPassword(u.ID, hashPassword(fs.Arg(1))); err != nil {
		return err
	}
	st.DeleteUserSessions(u.ID, "")
	st.UpdateUser(u.ID, u.Role, false, u.Routers)
	fmt.Println("Đã đặt lại mật khẩu và mở khoá cho", u.Username)
	return nil
}

func Run(ctx context.Context, cfg *Config) error {
	log.SetFlags(log.Ldate | log.Ltime)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	abs, _ := filepath.Abs(cfg.DataDir)
	cfg.DataDir = abs
	st, err := OpenStore(filepath.Join(cfg.DataDir, "draypulse.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	box, err := LoadBox(filepath.Join(cfg.DataDir, "secret.key"))
	if err != nil {
		return err
	}
	settings, err := NewSettingsStore(st, box)
	if err != nil {
		return err
	}

	srv := &Server{cfg: cfg, st: st, box: box, settings: settings, lim: newLimiter(), pwSem: make(chan struct{}, 2)}
	n, err := st.CountUsers()
	if err != nil {
		return err
	}
	if n == 0 {
		if cfg.AdminPassword != "" {
			if err := validPassword(cfg.AdminPassword); err != nil {
				return fmt.Errorf("DRAYPULSE_ADMIN_PASSWORD: %w", err)
			}
			if _, err := st.CreateUser(cfg.AdminUser, hashPassword(cfg.AdminPassword), "admin"); err != nil {
				return err
			}
			log.Printf("đã tạo tài khoản quản trị %q từ cấu hình", cfg.AdminUser)
		} else {
			srv.setupCode = setupCode()
			codeFile := filepath.Join(cfg.DataDir, setupCodeFile)
			if err := writeFileAtomic(codeFile, []byte(srv.setupCode+"\n"), 0o600); err != nil {
				log.Printf("không ghi được %s: %v", codeFile, err)
			}
			log.Printf("================================================")
			log.Printf("  LẦN CHẠY ĐẦU – mở trình duyệt và nhập mã: %s", srv.setupCode)
			log.Printf("  (mã cũng được lưu trong %s)", codeFile)
			log.Printf("================================================")
		}
	}
	if cfg.Demo {
		if err := seedDemo(st); err != nil {
			return err
		}
	}

	hub := NewHub(st, box, settings, cfg.Demo)
	notifier := NewNotifier(st, settings)
	hub.notify, notifier.hub = notifier, hub
	auditor := NewAuditor(hub, st, settings, notifier)
	srv.hub, srv.n, srv.audit = hub, notifier, auditor
	if err := st.FailStaleAudits(); err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := hub.Start(runCtx); err != nil {
		return err
	}
	if cfg.Syslog != "" && cfg.Syslog != "off" {
		if err := hub.StartSyslog(runCtx, cfg.Syslog); err != nil {
			log.Printf("không mở được cổng syslog %s: %v (bỏ qua)", cfg.Syslog, err)
		}
	}
	auditor.ctx = runCtx
	go auditor.Run(runCtx)
	go notifier.Run(runCtx)
	go notifier.RunBots(runCtx)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(os.Stderr, "http: ", log.LstdFlags),
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("không mở được cổng %s: %w", cfg.Listen, err)
	}
	scheme := "http"
	switch cfg.TLS {
	case "auto":
		cert, err := loadOrCreateCert(cfg.DataDir)
		if err != nil {
			return err
		}
		httpSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		scheme = "https"
	case "files":
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("đọc chứng chỉ: %w", err)
		}
		httpSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		scheme = "https"
	}
	errCh := make(chan error, 1)
	go func() {
		if httpSrv.TLSConfig != nil {
			errCh <- httpSrv.ServeTLS(ln, "", "")
		} else {
			errCh <- httpSrv.Serve(ln)
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	log.Printf("DrayPulse %s đang chạy: %s://<IP-máy-này>:%s  (dữ liệu: %s)", Version, scheme, port, cfg.DataDir)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			cancel()
			hub.Wait()
			return err
		}
	}
	log.Printf("đang dừng...")
	shutCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	httpSrv.Shutdown(shutCtx)
	cancel()
	hub.Wait()
	log.Printf("đã dừng an toàn")
	return nil
}

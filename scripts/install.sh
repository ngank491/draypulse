#!/bin/sh
# Cài DrayPulse thành dịch vụ systemd trên Linux (Debian/Ubuntu/Raspberry Pi OS…).
# Chạy lại script để nâng cấp: dữ liệu trong /var/lib/draypulse được giữ nguyên.
#
#   sudo ./install.sh [--port 8080] [--syslog 5514] [--uninstall]
set -eu

PORT=8080
SYSLOG=5514
UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT=$2; shift 2 ;;
    --syslog) SYSLOG=$2; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) echo "Tham số không hợp lệ: $1"; exit 1 ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "Hãy chạy bằng sudo: sudo $0 $*"; exit 1; }
command -v systemctl >/dev/null || { echo "Máy này không có systemd."; exit 1; }

UNIT=/etc/systemd/system/draypulse.service
DATA=/var/lib/draypulse

if [ "$UNINSTALL" = 1 ]; then
  systemctl disable --now draypulse 2>/dev/null || true
  rm -f "$UNIT" /usr/local/bin/draypulse
  systemctl daemon-reload
  echo "Đã gỡ DrayPulse. Dữ liệu vẫn còn ở $DATA (xoá tay nếu không cần)."
  exit 0
fi

DIR=$(cd "$(dirname "$0")" && pwd)
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Kiến trúc $(uname -m) chưa có sẵn trong gói này."; exit 1 ;;
esac
BIN="$DIR/draypulse-linux-$ARCH"
[ -f "$BIN" ] || BIN="$DIR/draypulse" # archive built by scripts/build.sh
[ -f "$BIN" ] || { echo "Không thấy file chạy draypulse cho $ARCH trong $DIR"; exit 1; }

echo "→ Cài $BIN vào /usr/local/bin/draypulse"
systemctl stop draypulse 2>/dev/null || true
install -m 0755 "$BIN" /usr/local/bin/draypulse

if ! id draypulse >/dev/null 2>&1; then
  echo "→ Tạo user hệ thống draypulse"
  useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin draypulse
fi
mkdir -p "$DATA"
chown draypulse:draypulse "$DATA"
chmod 0700 "$DATA"

echo "→ Tạo dịch vụ $UNIT (web :$PORT, syslog UDP :$SYSLOG)"
cat > "$UNIT" <<EOF
[Unit]
Description=DrayPulse – giám sát router DrayTek
After=network-online.target
Wants=network-online.target

[Service]
User=draypulse
Group=draypulse
Environment=TZ=Asia/Ho_Chi_Minh
ExecStart=/usr/local/bin/draypulse -data $DATA -listen :$PORT -syslog :$SYSLOG
Restart=always
RestartSec=5
# ping thiết bị (ICMP) và cổng syslog < 1024 nếu cần
AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now draypulse
sleep 3
if ! systemctl is-active --quiet draypulse; then
  echo "DrayPulse không chạy được, xem log:"
  journalctl -u draypulse -n 30 --no-pager
  exit 1
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "✓ DrayPulse $(/usr/local/bin/draypulse version | awk '{print $2}') đang chạy: http://${IP:-<IP-máy-này>}:$PORT"
if [ -f "$DATA/setup-code.txt" ]; then
  echo "  Mã khởi tạo lần đầu: $(cat "$DATA/setup-code.txt")"
fi
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  echo
  echo "UFW đang bật. Mở cổng cho mạng LAN, ví dụ:"
  echo "  sudo ufw allow from 192.168.0.0/16 to any port $PORT proto tcp comment 'DrayPulse web'"
  echo "  sudo ufw allow from 192.168.0.0/16 to any port $SYSLOG proto udp comment 'DrayPulse syslog'"
fi

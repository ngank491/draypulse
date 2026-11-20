# DrayPulse – giám sát router DrayTek Vigor gọn nhẹ

Một file chạy duy nhất (~20 MB RAM), không cần Node.js, Docker hay database riêng.
Chạy trên Windows, Linux, macOS, Raspberry Pi, Docker và Home Assistant OS.

DrayPulse là bản "anh em" của **NetPulse** (giám sát MikroTik): giữ nguyên lõi cảnh báo, giao diện, sơ đồ mạng,
Telegram/Zalo và trợ lý AI, nhưng lớp đọc router được viết lại cho **DrayTek Vigor (DrayOS 3.9 / 4.x)**.

## Tính năng

- **Ba cách đọc router, bổ sung cho nhau**
  - **SNMP v1/v2c/v3**: CPU, RAM, uptime, model, firmware, lưu lượng từng cổng LAN/WAN, danh sách VPN đang kết nối (DRAYTEK-MIB).
  - **Telnet / SSH** (tuỳ chọn): trạng thái WAN chi tiết, IP public, bảng ARP và DHCP lease (client, tên máy, cổng LAN), kiểm tra Internet riêng từng WAN bằng `ip ping … WANx`. Chỉ gửi lệnh xem trong danh sách cố định.
  - **Syslog** (tuỳ chọn): router tự đẩy sự kiện VPN kết nối/ngắt, WAN lên/xuống, đăng nhập quản trị.
- **Tổng quan nhiều router**: CPU, RAM, uptime, firmware, trạng thái WAN và số thiết bị lỗi trên một màn hình.
- **WAN đa đường**: link + Internet từng WAN, IP public, đổi IP, tự gợi ý WAN đang bật trên router.
- **VPN**: bảng LAN-to-LAN / Remote Dial-in đang kết nối, cảnh báo VPN PPTP.
- **Theo dõi thiết bị**: ping camera, switch, AP, NAS… mỗi 30 giây (từ máy DrayPulse hoặc từ router). Độ trễ và tỷ lệ sẵn sàng 24 giờ.
- **Client**: gộp DHCP lease và ARP; tên máy (HOST ID, NetBIOS, mDNS), hãng theo MAC, cổng LAN (P1…).
- **Sơ đồ mạng kéo thả**, **biểu đồ lịch sử** lưu lượng/CPU/RAM từ 1 giờ đến 30 ngày (bộ đếm 32-bit của DrayOS được tự nối dài thành 64-bit, không bị nhảy số khi tràn).
- **Cảnh báo Telegram và Zalo**: chống báo nhầm (2 lần liên tiếp), không mất tin (lưu trước khi gửi), nhắc lại, bản tin hằng ngày, bot trả lời `/status`.
- **Kiểm tra bảo mật & hiệu suất** cho DrayTek: quản trị từ Internet, SNMP community mặc định, Telnet không mã hoá, firmware cũ, VPN PPTP, WAN bật nhưng chết, CPU/RAM cao… Có trợ lý AI tuỳ chọn (Claude, ChatGPT, Gemini, DeepSeek, Ollama…) – mật khẩu không bao giờ rời máy, IP public/MAC được che.
- **Phân quyền** quản trị viên / người xem, **sao lưu một chạm**.

📘 **Hướng dẫn chi tiết: [docs/HUONG-DAN.md](docs/HUONG-DAN.md)** · Nguồn tham khảo kỹ thuật: [docs/DRAYTEK-NGUON.md](docs/DRAYTEK-NGUON.md)

## Dùng thử ngay (không cần router)

```bash
./draypulse -demo -data ./demo-data
```

Chế độ demo chạy một **Vigor2927 ảo** bên trong DrayPulse (SNMP agent + Telnet DrayOS giả lập trên 127.0.0.1), nên mọi dữ liệu đi qua đúng đường đọc thật: 2 WAN (VNPT, Viettel – WAN2 mất Internet 2 phút mỗi 15 phút), 2 VPN, 10 client, thiết bị chập chờn để thấy cảnh báo.

## Cài đặt

### Windows

1. Tải `draypulse-…-windows-amd64.zip` ở trang Releases rồi giải nén.
2. Nhấp đúp `draypulse.exe`. Cửa sổ sẽ hiện **mã khởi tạo**.
3. Mở `http://IP-máy-này:8080`, nhập mã khởi tạo rồi tạo tài khoản quản trị.

Dữ liệu nằm trong thư mục `data` cạnh file exe. Khi nâng cấp, chỉ cần thay file exe.

### Linux / Raspberry Pi

```bash
tar xzf draypulse-*-linux-arm64.tar.gz && cd draypulse-*/
./draypulse -data /var/lib/draypulse
```

Ví dụ chạy như dịch vụ systemd (`/etc/systemd/system/draypulse.service`):

```ini
[Unit]
Description=DrayPulse
After=network-online.target
[Service]
ExecStart=/usr/local/bin/draypulse -data /var/lib/draypulse
DynamicUser=yes
StateDirectory=draypulse
Restart=always
[Install]
WantedBy=multi-user.target
```

### Docker

```bash
docker run -d --name draypulse --restart unless-stopped -p 8080:8080 -p 5514:5514/udp -v draypulse-data:/data ghcr.io/ngank491/draypulse:latest
```

```bash
docker logs draypulse
```

Lệnh thứ hai hiện mã khởi tạo. Có thể dùng `compose.yaml` thay cho lệnh `docker run`.

### Home Assistant OS

Thêm `https://github.com/ngank491/draypulse` vào **Settings → Add-ons → Add-on Store → ⋮ → Repositories**, cài **DrayPulse**, đặt `admin_password` rồi Start.

Image Docker/Home Assistant chỉ được CI build khi đẩy tag phiên bản (ví dụ `git tag v0.1.0 && git push origin v0.1.0`). Ở lần đầu, vào GitHub → Packages → `draypulse` và `draypulse-ha` → Package settings → đổi sang **Public** để Home Assistant và Docker tải được mà không cần đăng nhập.

### Tuỳ chọn

| Cờ / biến môi trường | Ý nghĩa |
|---|---|
| `-data` / `DRAYPULSE_DATA` | Thư mục dữ liệu (mặc định `./data`) |
| `-listen` / `DRAYPULSE_LISTEN` | Địa chỉ lắng nghe (mặc định `:8080`) |
| `-tls auto` / `DRAYPULSE_TLS=auto` | Bật HTTPS bằng chứng chỉ tự ký, lưu trong thư mục dữ liệu |
| `-tls-cert`, `-tls-key` | Dùng chứng chỉ riêng của bạn |
| `DRAYPULSE_ADMIN_PASSWORD` | Tạo admin ngay ở lần chạy đầu, không cần mã khởi tạo |
| `-trust-proxy` | Tin header `X-Forwarded-*` (chỉ bật khi đứng sau reverse proxy) |
| `-syslog` / `DRAYPULSE_SYSLOG` | Cổng UDP nhận syslog từ router (mặc định `:5514`, `off` để tắt) |
| `-demo` | Tạo một router Vigor2927 mô phỏng (SNMP + Telnet giả lập chạy bên trong) để dùng thử |

## Kết nối router (tóm tắt)

Trên router (Web UI hoặc Telnet/SSH từ LAN), với `192.168.1.4` là máy chạy DrayPulse:

1. **SNMP** – *System Maintenance → SNMP*: bật SNMP Agent, Get Community khó đoán, Manager Host IP = `192.168.1.4`.
   ```
   mngt snmp -e 1 -b 1 -g <Community> -m 192.168.1.4
   ```
2. **SSH/Telnet** (nên có) – *System Maintenance → Management*: bật SSH Server cho LAN. Không bật "Allow management from the Internet".
3. **Syslog** (tuỳ chọn) – *System Maintenance → SysLog / Mail Alert*:
   ```
   sys syslog -a 1 -s 1 -i 192.168.1.4 -d 5514 -f 0 -v 1 -w 1 -r 1 -e 0
   ```
4. Trong DrayPulse: **Router → Thêm router**, nhập IP, community, tài khoản SSH → **Kiểm tra kết nối** → chọn WAN1/WAN2 → Lưu.

Form **Thêm router** có mục **🛠 Tạo lệnh cấu hình router** sinh sẵn community ngẫu nhiên và các lệnh trên cho đúng router của bạn.

| Model đã đối chiếu dữ liệu thật | Nguồn |
|---|---|
| Vigor 2927 / 2927Lac (DrayOS 4.4–4.5) | walk SNMP, `sys version`, `show status`, `wan status` |
| Vigor 2962 (4.3) | walk SNMP |
| Vigor 3912S (4.4) | `ip arp status`, `srv dhcp status`, `ip ping` (User Guide) |

Vigor 3900/2960 (Linux, CLI khác) và DrayOS 5 (Vigor 2136ax/2767/167, CLI `vigor>`) chưa được hỗ trợ đầy đủ qua CLI; SNMP chuẩn vẫn dùng được.

## Vận hành

- **Quên mật khẩu**: dừng DrayPulse rồi chạy `draypulse reset-password -data <thư mục> admin "MatKhauMoi123"`.
- **Sao lưu**: vào **Cài đặt → Tải bản sao lưu**. Để khôi phục, dừng DrayPulse, chép file vào `<data>/draypulse.db` và giữ nguyên `secret.key`.
- **Dữ liệu**: `draypulse.db` (SQLite, WAL), `secret.key` (khoá AES-256-GCM để mã hoá mật khẩu router và Bot Token). Lịch sử được dọn tự động theo số ngày đặt trong Cài đặt.
- **Bảo mật**:
  - Mật khẩu băm bằng PBKDF2-SHA256 (300.000 vòng).
  - Cookie `HttpOnly` và `SameSite`. Mọi yêu cầu thay đổi phải có header riêng chống CSRF.
  - Có CSP chặt. Giao diện không dùng `innerHTML`, nên tên lấy từ router không chèn được mã.
  - Mật khẩu router, community và mật khẩu SNMPv3 được mã hoá AES-256-GCM, không bao giờ trả về giao diện.
  - CLI chỉ gửi lệnh *xem* trong danh sách cố định (kiểm tra ngay trong mã, có test); mọi lệnh khác bị chặn.

## Phát triển

```bash
go test -race ./...
go run . -demo -data ./data -listen :8080
```

```bash
VERSION=0.1.0 ./scripts/build.sh
```

Lệnh build tạo các gói cho mọi nền tảng trong `dist/`. Giao diện là HTML/CSS/JS thuần trong `internal/app/web`, được nhúng vào file chạy, không cần bước build.

# DrayPulse – dữ liệu DrayTek và nguồn tham khảo

Tài liệu kỹ thuật cho người phát triển: DrayPulse đọc gì từ router Vigor, bằng cách nào, và dựa trên nguồn nào.
Mẫu output dùng trong test (`internal/app/testdata/drayos/`) được viết lại theo đúng định dạng của các nguồn dưới đây, với số liệu giả.

## SNMP

| Dữ liệu | OID | Ghi chú |
|---|---|---|
| Model + firmware | `sysDescr` `.1.3.6.1.2.1.1.1.0` | `DrayTek Corporation, Router Model: Vigor2962, Version: 4.3.2.5, Build Date/Time:Sep 28 2023 12:10:20` |
| Nhận diện | `sysObjectID` = `.1.3.6.1.4.1.7367` | Vigor 3900 (Linux) trả `.1.3.6.1.4.1.8072.3.2.10` |
| Uptime | `sysUpTime` `.1.3.6.1.2.1.1.3.0` | |
| CPU % | `hrProcessorLoad` `.1.3.6.1.2.1.25.3.3.1.2` | DrayOS dùng chỉ số `.0` (không chuẩn) → DrayPulse walk cột |
| Model | `.1.3.6.1.4.1.7367.3.1.0` | DRAYTEK-MIB `routerModel` |
| Firmware | `.1.3.6.1.4.1.7367.3.2.0` | `4.4.2.3 drayos2015_V2927_442_Release` |
| Ngày build | `.1.3.6.1.4.1.7367.3.3.0` | |
| RAM % | `.1.3.6.1.4.1.7367.3.7.0` | `memoryUsage` |
| Nhiệt độ USB | `.1.3.6.1.4.1.7367.1.1.0` | `No sensor` khi không có cảm biến |
| VPN đang kết nối | `.1.3.6.1.4.1.7367.2.1.<cột>.<dòng>` | cột 3 tên profile, 4 kiểu, 5 IP phía kia, 6 WAN, 7 mạng phía kia, 10/11 tốc độ, 12 thời gian |
| Interface | IF-MIB `ifTable` | Tên: `LAN`, `WAN1…WAN7`, `V-WAN8+`, `LAN_PORT1-6`, `Loopback`. **Chỉ có bộ đếm 32-bit** – DrayPulse tự nối dài thành 64-bit |
| IP | `ipAddrTable` `.1.3.6.1.2.1.4.20` | |

Không có trên các walk đã xem (2920/2927/2962): `ifXTable` (bộ đếm 64-bit), `ipNetToMediaTable` (ARP), `hrStorage` → ARP/DHCP lấy qua CLI.

## CLI (Telnet / SSH, DrayOS 3.x/4.x)

- Đăng nhập Telnet: `Account:` → `Password:` → prompt `<TênRouter>> ` (mặc định `DrayTek> `; vài bản chỉ in `> `). DrayPulse học prompt sau khi đăng nhập.
- Phân trang: `--- MORE ---   ['q': Quit, 'Enter': New Lines, 'Space Bar': Next Page] ---` → gửi dấu cách.
- SSH: **không có kênh exec**, phải dùng shell tương tác; firmware cũ cần thuật toán cũ (`diffie-hellman-group1-sha1`, `3des-cbc`, `ssh-rsa`) – DrayPulse cho phép làm dự phòng.
- Lệnh DrayPulse dùng (danh sách cố định trong `cli.go`, có test):

| Lệnh | Dùng cho |
|---|---|
| `sys version` | model, firmware, tên router |
| `wan status` / `show status` | trạng thái, kiểu, IP, gateway, DNS, uptime từng WAN |
| `ip arp status` | client đang hoạt động, HOST ID, interface, VLAN, cổng LAN |
| `srv dhcp status` | DHCP lease |
| `ip ping <IP> <AUTO\|WANx>` | kiểm tra Internet riêng từng WAN |
| `vlan status`, `show lan` | VLAN (VID, cổng thành viên, subnet) và subnet LAN + DHCP pool |
| `mngt rmtcfg status`, `sys iface`, `ip dhcpc status` | chỉ cho phần kiểm tra bảo mật |

**Lệnh ghi (chỉ dùng cho chặn client, danh sách riêng `cliWriteAllowed`):**

| Lệnh | Ý nghĩa |
|---|---|
| `ipf set -v` / `ipf set -d <bộ lọc>` / `ipf set -d 0` | đọc / bật / tắt Data Filter (chỉ tắt nếu DrayPulse đã bật) |
| `ipf rule ?` | số bộ lọc và số luật mỗi bộ của firmware |
| `ipf rule <s> <r> -v` | đọc luật (trạng thái, ghi chú, nguồn, Pass/Block) |
| `ipf rule <s> <r> -e 1 -D 0 -s "g 1 32" -F "1 0" -m "0 0" -M "DrayPulse"` | tạo/bật luật chặn: LAN → WAN, nguồn nhóm 32, Block Immediately, MAC Bind non-strict |
| `ipf rule <s> <r> -s "g 2 31"` / `"g 2 0"` | thêm/bỏ nhóm 31 làm nguồn thứ hai |
| `ipf rule <s> <r> -e 0` / `-U 0` | tắt luật / chuyển luật lên một bậc |
| `object ip obj <100–192> -v / -n DP-… / -i 1 / -a 4 <mac> / -a 1 <ip> / -a 0 0.0.0.0 0.0.0.0` | đối tượng IP của DrayPulse |
| `object ip grp <31|32> -v / -n DrayPulse1|2 / -i 1 / -a "<12 số>"` | nhóm IP của DrayPulse |
| `ip bindmac show` / `del <IP>` / `off`, `ip arp del <IP> LAN` | chỉ để dọn mục chặn của bản 0.4–0.6 khi Bỏ chặn tất cả |

Không có `sys commit`, `sys reboot`, lệnh xoá luật/nhóm/đối tượng khác. Cú pháp theo CLI Reference DrayOS 4.4 và đã thử trên Vigor 3912S 4.4.3.2 và Vigor2926 plus 4.4.3.

## Syslog

UDP, dạng RFC3164 `<PRI>Mmm dd hh:mm:ss <TênRouter>: <nội dung>`. Facility theo nhóm: local0 firewall, local1 VPN, local2 truy cập người dùng, local3 kết nối, local4 WAN, local5 router/DSL (chỉ local0 = firewall được DrayTek xác nhận chính thức). Mẫu VPN: `[H2L][UP][SSLTunnel][@user]`, `[L2L][DOWN]…`.

## Chưa hỗ trợ / chưa kiểm chứng

- DrayOS 5 (Vigor 2136ax, 2767, 2928, 167, C410ax): CLI khác (`vigor>`, `exec sysinfo`), web API `cgi-bin/webproc.cgi`. SNMP chuẩn vẫn dùng được.
- Vigor 3900/2960 (Linux): CLI `enable` / `status system`.
- Định dạng chính xác của `mngt rmtcfg status` và các dòng syslog WAN – quy tắc kiểm tra chỉ báo khi output ghi rõ "enabled/on".
- Payload của `sys webhook`.

## Nguồn

- LibreNMS – định nghĩa OS DrayTek và walk SNMP thật (2920, 165, 2962, 3900): <https://github.com/librenms/librenms> (`resources/definitions/os_detection/draytek.yaml`, `tests/snmpsim/draytek*.snmprec`)
- DRAYTEK-MIB: <https://mibs.observium.org/mib/DRAYTEK-MIB/>
- kpeacocke/ansible-collection-draytek – mẫu output Vigor 2927/2927Lac, prompt và phân trang: <https://github.com/kpeacocke/ansible-collection-draytek>
- jooservices/vigor3912s-mcp – tham chiếu lệnh Telnet (trích User Guide Vigor3912), ghi chú SSH: <https://github.com/jooservices/vigor3912s-mcp>
- xoofx/draytek-watcher – parser `wan status` (Vigor 2927): <https://github.com/xoofx/draytek-watcher>
- SuperQ/draytek_exporter (Go, DrayOS 5 web API): <https://github.com/SuperQ/draytek_exporter>
- skornehl/ha-draytek-vigor (Home Assistant, DrayOS 5): <https://github.com/skornehl/ha-draytek-vigor>
- wangnanlena/DraytekSyslog, Fastvue/draytekvpnanalyzer – định dạng syslog
- Zabbix templates: bitfinity-nl/zbx-draytek, lamanh0402/zbx6.2-draytek-vigor3910
- DrayTek security advisories: <https://www.draytek.com/about/security-advisory>

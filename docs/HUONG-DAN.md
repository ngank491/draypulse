# Hướng dẫn sử dụng DrayPulse

Tài liệu này hướng dẫn từng bước:

1. [Đăng nhập lần đầu](#1-đăng-nhập-lần-đầu)
2. [Thêm router DrayTek](#2-thêm-router-draytek) – SNMP, Telnet/SSH và Syslog
3. [Theo dõi thiết bị và đặt tên client](#3-theo-dõi-thiết-bị-và-đặt-tên-client) – kèm [theo dõi VLAN](#theo-dõi-vlan) và [chặn client](#chặn-client)
4. [Nhận cảnh báo qua Telegram](#4-nhận-cảnh-báo-qua-telegram)
5. [Nhận cảnh báo qua Zalo](#5-nhận-cảnh-báo-qua-zalo)
6. [DrayPulse cảnh báo những gì](#6-draypulse-cảnh-báo-những-gì)
7. [Trợ lý AI kiểm tra bảo mật và hiệu suất](#7-trợ-lý-ai-kiểm-tra-bảo-mật-và-hiệu-suất)
8. [Xử lý sự cố](#8-xử-lý-sự-cố)

Trong hướng dẫn, `192.168.1.4` là IP máy chạy DrayPulse và `192.168.1.1` là router. Hãy thay bằng địa chỉ thực tế của bạn.

> Hướng dẫn này cũng có ngay trong DrayPulse: menu **Hướng dẫn** (các lệnh mẫu tự dùng IP DrayPulse bạn đang mở). Ngoài ra:
> - form **Thêm router** có mục **🛠 Tạo lệnh cấu hình router**: sinh sẵn community SNMP và từng lệnh DrayOS (kèm đường dẫn Web UI tương ứng) cho router của bạn;
> - form **Thêm tài khoản AI** hiện các bước lấy API key của nhà cung cấp đang chọn, kèm nút mở trang lấy key.

---

## 1. Đăng nhập lần đầu

1. Mở trình duyệt, vào `http://192.168.1.4:8090` (hoặc cổng bạn đã chọn).
2. Ở lần chạy đầu, trang hiện **Khởi tạo DrayPulse** và hỏi **mã khởi tạo**. Mã có ở một trong hai nơi:
   - cửa sổ hoặc log của DrayPulse (dòng `LẦN CHẠY ĐẦU – … nhập mã: XXXX-XXXX`);
   - file `setup-code.txt` trong thư mục dữ liệu, ví dụ:
     ```bash
     cat ~/.local/share/draypulse/setup-code.txt
     ```
3. Nhập mã, đặt tên đăng nhập và mật khẩu quản trị (ít nhất 10 ký tự). Mã chỉ dùng được một lần.

> Nếu từ máy khác không mở được trang, kiểm tra tường lửa của server. Ví dụ với UFW, chỉ mở cho mạng LAN:
> ```bash
> sudo ufw allow from 192.168.1.0/24 to any port 8090 proto tcp comment 'DrayPulse LAN'
> ```

---

## 2. Thêm router DrayTek

DrayPulse đọc router Vigor (DrayOS 3.9 / 4.x: Vigor 2135, 2765, 2865, 2866, 2927, 2962, 3910, 3912…) bằng ba cách bổ sung cho nhau. Chỉ cần **SNMP** là đã giám sát được; bật thêm **Telnet/SSH** để có đầy đủ dữ liệu.

| Dữ liệu | SNMP | Telnet/SSH | Syslog |
|---|:-:|:-:|:-:|
| CPU, RAM, uptime, model, firmware | ✔ | (firmware) | |
| Lưu lượng từng cổng LAN / WAN | ✔ | | |
| Link WAN lên/xuống | ✔ | ✔ | |
| VPN đang kết nối (LAN-to-LAN, Dial-in) | ✔ | | |
| IP public, gateway, kiểu kết nối từng WAN | | ✔ | |
| Kiểm tra Internet riêng từng WAN (`ip ping … WAN1`) | | ✔ | |
| Client: bảng ARP, DHCP lease, tên máy, cổng LAN | | ✔ | |
| Sự kiện VPN kết nối/ngắt, WAN, đăng nhập quản trị | | | ✔ |

> **An toàn:** DrayPulse chỉ gửi các lệnh *xem* nằm trong danh sách cố định (`sys version`, `wan status`, `ip arp status`, `srv dhcp status`, `show status`, `ip ping <IP> WANx`, `mngt rmtcfg status`…). Mọi lệnh khác bị chặn ngay trong phần mềm, kể cả khi trợ lý AI yêu cầu.

### Bước D1. Bật SNMP trên router

**Web UI:** *System Maintenance → SNMP*

- Tick **Enable SNMP Agent**.
- **Get Community**: đặt chuỗi khó đoán (tối đa 23 ký tự), **không** để `public`.
- **Manager Host IP**: IP máy DrayPulse (`192.168.1.4`), để router chỉ trả lời máy này.
- Nếu router có **SNMPv3 Agent**: nên dùng v3 với *Auth = SHA*, *Privacy = AES*.

**Hoặc bằng lệnh** (Telnet/SSH vào router từ LAN):

```
mngt snmp -e 1 -b 1 -g <Community> -m 192.168.1.4
```

SNMPv3:

```
mngt snmp -e 1 -c 1 -o draypulse -p 2 -q <MatKhauXacThuc> -r 6 -u <MatKhauMaHoa> -m 192.168.1.4
```

### Bước D2. (Nên có) Bật SSH hoặc Telnet cho LAN

**Web UI:** *System Maintenance → Management → Management Port Setup / LAN Access*: bật **SSH Server** (cổng 22) – hoặc Telnet nếu model cũ không có SSH – và chỉ cho phép từ LAN.

- **Không** tick *Allow management from the Internet*. Giao diện quản trị DrayTek mở ra Internet đã nhiều lần bị khai thác hàng loạt; nếu cần quản trị từ xa, hãy đi qua VPN.
- DrayPulse đăng nhập bằng tài khoản quản trị của router (DrayOS không có tài khoản CLI chỉ-đọc), mật khẩu được mã hoá AES-256 trong `secret.key`.

### Bước D3. (Tuỳ chọn) Gửi syslog về DrayPulse

DrayPulse nhận syslog ở **UDP 514** (cổng mặc định của DrayTek) và **5514**. Bộ cài `install.sh` cấp quyền để dùng cổng 514; nếu chạy tay bằng user thường, cổng 514 không mở được, hãy đặt router gửi tới 5514. Đổi bằng `-syslog :514,:5514`, tắt bằng `-syslog off`.

**Web UI:** *System Maintenance → SysLog / Mail Alert → Syslog Access Setup*: bật **Syslog Save to Syslog Server**, *Server IP* = `192.168.1.4`, *Destination Port* = `514`; chọn **VPN Log**, **WAN Log**, **Router/DSL information**. Không cần Firewall Log (rất nhiều dòng).

```
sys syslog -a 1 -s 1 -i 192.168.1.4 -d 514 -f 0 -v 1 -w 1 -r 1 -e 0
```

DrayPulse gán gói syslog cho router khi **IP gửi** trùng địa chỉ router đã khai báo, hoặc tên router trong dòng syslog trùng tên router. Router ở chi nhánh/qua VPN thường gửi từ IP khác: mở tab **Syslog** của router – khung chẩn đoán liệt kê các địa chỉ đang gửi syslog mà chưa gán cho router nào, bấm **Gán** là xong. Tab cũng cho biết DrayPulse đang nghe cổng nào, đã nhận bao nhiêu dòng, và có bộ lọc theo loại log (VPN, WAN, Firewall…).

> Nếu server có tường lửa, mở cổng cho mạng LAN:
> ```bash
> sudo ufw allow from 192.168.1.0/24 to any port 514,5514 proto udp comment 'DrayPulse syslog'
> ```

### Bước D4. Thêm router trong DrayPulse

1. Vào **Router → + Thêm router**.
2. Nhập **Tên hiển thị** và **Địa chỉ router** (IP LAN, IP qua VPN, hoặc tên miền).
3. Phần **SNMP**: chọn phiên bản, nhập community (hoặc user/mật khẩu v3).
4. Phần **Telnet / SSH**: chọn SSH/Telnet, nhập tài khoản quản trị router.
5. Bấm **Kiểm tra kết nối**. Kết quả hiện model, firmware, số interface và các WAN có trên router.
6. Ở **WAN cần theo dõi**, bấm tên WAN được gợi ý (`WAN1`, `WAN2`…) và đặt tên nhà mạng.
7. Bấm **Thêm router**.

Router ở chi nhánh khác: nối về bằng VPN LAN-to-LAN (IPsec/WireGuard) rồi khai báo IP LAN của router chi nhánh – không mở SNMP/Telnet ra Internet.

**Thiết bị LAN được ping từ đâu?** Mặc định từ máy DrayPulse (cần đi tới được mạng LAN đó). Nếu DrayPulse ở mạng khác và không có đường tới thiết bị, chọn **Ping thiết bị LAN = Từ router** (cần Telnet/SSH).

> Mỗi lần ping qua router mất khoảng 5 giây và dùng chung phiên Telnet/SSH duy nhất với việc đọc ARP/DHCP và chặn client. Theo dõi nhiều thiết bị (trên khoảng 5) bằng **Từ router** làm phiên này bận liên tục; nếu máy DrayPulse đi tới được các thiết bị đó, hãy để **Từ máy DrayPulse**.

---

## 3. Theo dõi thiết bị và đặt tên client

### Thiết bị theo dõi (ping định kỳ)

Dùng cho camera, switch, AP, NAS, máy in… mà bạn muốn được báo khi mất kết nối.

1. Mở router → tab **Thiết bị** → **+ Thêm thiết bị**, hoặc **Thêm từ DHCP/ARP** để chọn nhiều thiết bị một lúc.
2. Chọn **Nối với** để vẽ đúng sơ đồ (tab **Sơ đồ**, kéo thả rồi bấm **Lưu bố cục**).
3. Bật **Báo khi mất kết nối** và chọn **Khi vẫn chưa khắc phục** (nhắc lại sau 15 phút đến 2 giờ).

DrayPulse ping 2 gói mỗi 30 giây (từ máy DrayPulse, hoặc từ router nếu chọn). Thiết bị chỉ bị báo mất kết nối sau **2 lần liên tiếp** không phản hồi.

### Tab Client

Tab **Client** liệt kê mọi máy router thấy (DHCP lease và bảng ARP, đọc qua Telnet/SSH):

- **Trạng thái**: *Hoạt động* nếu máy có trong bảng ARP của router; *Ngừng* nếu không. **Cổng** là cổng LAN (P1, P2…) mà router ghi nhận.
- **Thời gian hoạt động / dừng**: đang hoạt động bao lâu (từ lúc nào); hoặc dừng lúc nào, đã bao lâu, và phiên hoạt động trước đó dài bao lâu.
- **Tên máy** lấy theo thứ tự: tên tự đặt → thiết bị theo dõi → DHCP (HOST ID) → NetBIOS / mDNS / DNS ngược (DrayPulse hỏi trực tiếp máy, cần cùng mạng). Nếu vẫn không có, hiện **hãng sản xuất** theo MAC.
- Máy ghi **MAC ngẫu nhiên** là điện thoại hoặc laptop bật "địa chỉ Wi-Fi riêng tư". Chúng thường không công bố tên. Bấm **Đặt tên** để gán tên. Tên gắn với MAC nên vẫn đúng khi IP thay đổi.

---

### Theo dõi VLAN

Tab **VLAN** (cần Telnet/SSH) đọc mỗi phút lệnh `vlan status` và `show lan` của router:

- **Bảng VLAN**: VLAN 0–15 đang dùng, VID, mức ưu tiên, subnet (LAN1, LAN2…), **cổng thành viên** (P1… màu xanh = có link, đỏ = mất link; S1…S4 là SSID Wi-Fi), số client đang hoạt động và mức dùng DHCP.
- **Bảng mạng LAN**: từng subnet, gateway, VLAN nào mang subnet đó, client và DHCP pool.
- Tab **Client** có thêm cột **VLAN** (theo bảng ARP của router).
- **Cảnh báo**: chức năng VLAN bị bật/tắt; một VLAN bị bật, tắt hoặc đổi VID/cổng/subnet (gửi Telegram/Zalo, vì một cổng bị chuyển sang mạng khác là thay đổi bảo mật); DHCP của một subnet dùng từ 90% địa chỉ (báo lại khi xuống dưới 80%).

DrayOS không có bộ đếm lưu lượng riêng cho từng VLAN qua SNMP; xem lưu lượng theo cổng LAN ở tab **Cổng**.

### Chặn client

Chặn một thiết bị khỏi mạng ngay từ DrayPulse, **không cần chuẩn bị gì trên router**:

1. **Router → Sửa** → tick **Cho phép DrayPulse chặn IP client** (cần Telnet/SSH) → Lưu.
2. Tab **Client** (hoặc danh sách client của một VLAN) → nút **Chặn** ở dòng thiết bị. Hoặc **+ Chặn MAC/IP** để nhập MAC/IP bất kỳ.

**Chặn theo thiết bị (MAC) – mặc định, khuyên dùng:**

- DrayPulse chặn mọi IP mà MAC đó đang dùng, rồi **kiểm tra bảng DHCP và ARP của router mỗi 15 giây** (kể cả khi chu kỳ đọc router dài hơn): router cấp IP mới nào cho thiết bị thì IP đó bị chặn ngay (ghi sự kiện "nhận IP mới … – đã chặn").
- Khi một IP từng bị chặn được thiết bị **khác** dùng lại – chỉ cần **một** nguồn (ARP, bảng DHCP hoặc syslog) thấy MAC khác chưa bị chặn trên IP đó – DrayPulse **nhả IP ngay** và không chặn lại IP đó chừng nào máy kia còn xuất hiện, để không chặn nhầm máy vô tội.
- Nếu router gửi syslog về DrayPulse (Bước D3) và dòng log có thông tin cấp IP DHCP, DrayPulse kiểm tra lại ngay (sau ~3 giây) thay vì chờ 15 giây. Dòng log chỉ được dùng để **nhả** IP (khi nó nêu đúng một IP LAN và một MAC), không bao giờ để chặn thêm.
- Chặn được cả thiết bị **chưa có mặt**: nhập MAC, khi nó xuất hiện sẽ bị chặn ngay.
- Tuỳ chọn **"Báo cho tôi khi thiết bị đổi MAC nhưng vẫn mang tên máy"**: điện thoại bật "địa chỉ Wi-Fi riêng tư" thường vẫn gửi cùng tên máy (HOST ID) khi xin DHCP. Khi **đúng một** MAC mới (chưa bị chặn) mang tên đó xuất hiện, DrayPulse **không tự chặn** mà ghi **gợi ý chặn** và gửi cảnh báo Telegram/Zalo. Ở tab **Client → Client bị chặn → Gợi ý chặn**, bấm **Chặn** để xác nhận hoặc **Bỏ qua** (MAC đã bỏ qua sẽ không bị gợi ý lại). Nếu nhiều máy cùng mang tên đó một lúc thì không gợi ý gì.
- **Tên máy phổ biến không bao giờ được dùng để nhận diện** (iPhone, iPad, android-\*, Galaxy-\*, Redmi-\*, OPPO-\*, vivo-\*, realme-\*… và tên dưới 3 ký tự). Chặn thiết bị có tên như vậy chỉ chặn theo MAC; sự kiện ghi rõ "không theo dõi tên máy … vì tên này phổ biến". Danh sách sửa ở **Cài đặt → Chặn client an toàn**.

> **Bài học từ v0.5.0:** trước đây tuỳ chọn theo tên máy tự chặn mọi MAC mới cùng tên. Một lần chặn máy tên "Redmi-12"/"iPhone" đã lan ra hàng trăm điện thoại vô tội. Từ bản này, theo tên máy chỉ còn là gợi ý cần người duyệt.

**An toàn khi chặn (Cài đặt → Chặn client an toàn):**

- **Không bao giờ chặn**: danh sách MAC và/hoặc IP (máy chủ, camera, máy quản trị, AP…). Chặn tay sẽ bị từ chối; DrayPulse không bao giờ tự chặn chúng, và nếu một mục đang bị chặn được thêm vào danh sách thì IP đó được **nhả** ở lần kiểm tra kế tiếp.
- **Tối đa số lượt tự động chặn mỗi giờ** (mặc định 5, tính riêng từng router): mỗi IP DrayPulse tự chặn (thiết bị bị chặn nhận IP mới) là một lượt. Nếu lần kiểm tra sắp vượt giới hạn, DrayPulse **không chặn thêm IP nào**, **tạm dừng tự động chặn** cho router đó, ghi sự kiện cảnh báo và gửi Telegram/Zalo. Việc nhả IP vẫn tiếp tục. Kiểm tra danh sách rồi bấm **Tiếp tục tự động chặn** ở tab Client. Chặn tay không bị giới hạn.
- **Tên máy phổ biến**: các mẫu tên (dùng `*` và `?`, không phân biệt hoa thường) không dùng để gợi ý chặn thiết bị đổi MAC.

**Bỏ chặn tất cả:** tab **Client → Client bị chặn → Bỏ chặn tất cả** (chỉ quản trị viên, có hộp thoại xác nhận). DrayPulse xoá **mọi mục DrayPulse** trong bảng Bind IP to MAC của router (kể cả mục sót lại không có trong danh sách), quên toàn bộ thiết bị/IP bị chặn và gợi ý chặn. Mục do bạn tạo được giữ nguyên; chức năng Bind IP to MAC chỉ được **tắt** nếu chính DrayPulse đã bật nó và bảng đã trống. Dùng khi chặn nhầm hàng loạt – không cần xoá tay từng mục trên router.

**Chỉ chặn IP:** tick "Chỉ chặn IP này" – dùng cho thiết bị đặt IP tĩnh mà bạn không biết MAC.

**Cách hoạt động:** DrayPulse dùng chức năng **LAN → Bind IP to MAC** của router. Mỗi IP bị chặn được gắn với một MAC không tồn tại (`02:dd:00:00:00:01`, ghi chú `DrayPulse`), nên router từ chối mọi gói tin từ IP đó: thiết bị không ra được Internet và không sang được mạng/VLAN khác. Các lệnh dùng: `ip bindmac show / on / off / add / del` – không lệnh nào khác.

- Chế độ thường (không strict): các IP không có trong bảng vẫn dùng bình thường. Khi không còn ai bị chặn, nếu chính DrayPulse đã bật chức năng thì sẽ tắt lại.
- DrayPulse **không sửa hay xoá mục do bạn tạo**. Nếu chức năng đang tắt mà bảng đã có mục của bạn, DrayPulse từ chối bật và báo rõ IP nào.
- Không chặn được: IP của router, gateway, máy chạy DrayPulse, IP ngoài mạng LAN.
- Mỗi thay đổi được đọc lại; nếu router không lưu, DrayPulse hoàn tác. Nút **Đối chiếu với router** so danh sách với bảng trên router.

**Giới hạn cần biết:**

- Thiết bị đổi sang **MAC hoàn toàn mới và đổi cả tên máy** thì với router là một thiết bị mới – không phần mềm nào nhận ra nó chỉ qua mạng. Bật **Cài đặt → Báo khi có thiết bị lạ lần đầu vào mạng** để được báo ngay và chặn tiếp. Cách triệt để duy nhất là **danh sách trắng**: chỉ thiết bị đã duyệt mới vào được mạng.
- Trong khoảng tối đa ~15 giây sau khi nhận IP mới (vài giây nếu có syslog DHCP), thiết bị có thể vào mạng trước khi bị chặn lại.
- Khi ARP/DHCP cho thấy IP mới của thiết bị bị chặn **cũng** đang có máy khác dùng, DrayPulse ưu tiên không chặn nhầm: IP đó không bị chặn cho tới khi chỉ còn thiết bị bị chặn dùng nó.
- Định dạng dòng syslog DHCP khác nhau theo firmware; nếu router không gửi thông tin cấp IP, DrayPulse vẫn kiểm tra mỗi 15 giây như bình thường.
- Máy cùng subnet vẫn liên lạc trực tiếp với nhau qua switch (không đi qua router).

---

### Session NAT của router

DrayPulse đọc `show session` mỗi phút: tổng session đang dùng / tối đa (ô **Session NAT** ở trang Tổng quan) và số session theo từng WAN (tab WAN). Khi bảng session đầy từ **85%** trở lên, DrayPulse gửi cảnh báo – đây là nguyên nhân hay gặp khiến mạng chậm, trang web không mở được (thường do camera P2P, phần mềm torrent, máy nhiễm virus). Hết cảnh báo khi xuống dưới 70%.

Session/băng thông **theo từng IP** (trang *Diagnostics → Data Flow Monitor* trên router) chưa có lệnh Telnet/SSH trong tài liệu DrayTek nên DrayPulse chưa đọc được. Bạn có thể thử các lệnh `ip session status`, `ip session show`, `ip dataflowmonitor status` trong công cụ **Thử lệnh xem trên router** và gửi kết quả để bổ sung.

### Phát hiện DHCP giả mạo

**Cài đặt → Phát hiện DHCP giả mạo**: tick "Dò DHCP server lạ mỗi 10 phút". DrayPulse gửi một gói DHCPDISCOVER trên mỗi cổng mạng của máy chạy nó và ghi lại mọi DHCP server trả lời (không nhận IP). Server không phải router đang giám sát – thường là modem hoặc router Wi-Fi gia đình cắm nhầm vào LAN, làm máy trạm nhận sai IP/gateway và "mất mạng" ngẫu nhiên – bị cảnh báo qua Telegram/Zalo (tối đa 6 giờ/lần cho mỗi server). Có nút **Dò ngay** và bảng kết quả lần dò gần nhất.

- Chỉ thấy các mạng/VLAN mà máy DrayPulse cắm vào (với VLAN khác, cần máy DrayPulse có cổng/sub-interface trong VLAN đó).
- Cần chạy bằng dịch vụ từ `install.sh` (quyền dùng cổng 68). Chỉ hỗ trợ khi DrayPulse chạy trên Linux.
- DHCP server hợp lệ khác (ví dụ một AP chạy DHCP cho mạng khách) điền vào ô "DHCP server hợp lệ khác".

### Thiết bị đang truy cập gì (Firewall log)

Tab **Syslog** → bảng **"Thiết bị đang truy cập gì"**: DrayPulse đọc các dòng Firewall log router gửi về, thống kê theo từng IP trong LAN (số kết nối, số đích, số lần bị chặn). Bấm một thiết bị để xem nó truy cập IP/cổng nào (kèm tên dịch vụ phổ biến: HTTPS, DNS, Remote Desktop, STUN gọi video, Apple/Google push…).

Bật trên router:

1. *Firewall → Filter Setup* (hoặc *General Setup → Default Rule*): bật **Syslog** cho rule cần theo dõi, ví dụ một rule hướng LAN/DMZ/RT/VPN → WAN, Source IP là IP Object chứa các máy cần theo dõi, Filter **Pass Immediately**, Syslog **Enable**.
2. *System Maintenance → SysLog / Mail Alert*: tick **Firewall Log**, Server IP = máy DrayPulse.

Firewall log rất nhiều dòng: chỉ nên bật cho nhóm IP cần theo dõi. DrayPulse giữ 20.000 kết nối gần nhất cho mỗi router trong bộ nhớ (mất khi khởi động lại).

### Thử lệnh xem trên router

*Router → Sửa → Telnet/SSH → Thử lệnh xem trên router*: chạy một lệnh **chỉ xem** trong danh sách (sys version, wan status, ip arp status, srv dhcp status, vlan status, show lan, show session, ip bindmac show, ip session status…) và xem nguyên văn output. Dùng khi một chức năng báo lỗi đọc dữ liệu: gửi output này để biết firmware của bạn in khác tài liệu thế nào.

---

## 4. Nhận cảnh báo qua Telegram

### Bước T1. Tạo bot

1. Trong Telegram, tìm **@BotFather** → gửi `/newbot`.
2. Đặt tên hiển thị, rồi đặt username kết thúc bằng `bot` (ví dụ `congty_draypulse_bot`).
3. BotFather trả về **token** dạng `123456789:AAH…`. Giữ bí mật token này.

### Bước T2. Lưu token trong DrayPulse

1. Vào **Cài đặt → Cảnh báo Telegram**, dán token vào **Bot Token**.
2. Bấm **Lưu cài đặt**. Huy hiệu chuyển thành **Đã có Bot Token**.

### Bước T3. Lấy Chat ID

- **Nhận cá nhân:** mở bot vừa tạo trong Telegram và bấm **Start** (gửi `/start`). Bot trả lời Chat ID.
- **Nhận trong nhóm:** thêm bot vào nhóm rồi gõ `/id` trong nhóm. Chat ID của nhóm là số âm, ví dụ `-1001234567890`.

Sau vài giây, Chat ID cũng hiện ở bảng **Tin nhắn gần đây gửi tới bot** trong Cài đặt. Bấm **Dùng làm Chat ID quản trị** để điền tự động.

### Bước T4. Lưu và gửi thử

1. Bấm **Lưu cài đặt**, rồi **Gửi tin thử**. Điện thoại phải nhận được "✅ DrayPulse đã kết nối Telegram thành công."
2. Muốn từng router báo vào một nhóm riêng: vào **Router → Sửa** và nhập Chat ID nhóm vào **Chat ID Telegram riêng cho router này**.

Gõ `/status` cho bot bất cứ lúc nào để xem tình trạng. Chat quản trị xem được mọi router; nhóm riêng chỉ xem được router của nhóm đó.

---

## 5. Nhận cảnh báo qua Zalo

DrayPulse dùng **Zalo Bot Platform** (bot chính thức của Zalo, miễn phí, không cần Official Account).

### Bước Z1. Tạo bot Zalo

1. Mở ứng dụng **Zalo** trên điện thoại, tìm Official Account **Zalo Bot Manager**.
2. Trong khung chat, mở menu và chọn **Tạo bot**. Ứng dụng **Zalo Bot Creator** mở ra.
3. Đặt tên bot **bắt đầu bằng chữ "Bot"** (ví dụ "Bot DrayPulse Công ty"), điền thông tin và bấm **Tạo Bot**.
4. Zalo gửi thông tin bot kèm **Bot Token** (dạng `12345678:abc-xyz…`) vào tài khoản của bạn. Giữ bí mật token này. Bạn có thể đặt lại token trong Zalo Bot Creator nếu bị lộ.

### Bước Z2. Lưu token trong DrayPulse

1. Vào **Cài đặt → Cảnh báo Zalo**, dán token vào **Bot Token**.
2. Bấm **Lưu cài đặt**.

### Bước Z3. Lấy Chat ID

1. Trong Zalo, mở cuộc trò chuyện với bot vừa tạo và nhắn **`id`**.
2. Bot trả lời "Chat ID của cuộc trò chuyện này: …". Chat ID cũng hiện ở bảng **Tin nhắn gần đây gửi tới bot** trong Cài đặt. Bấm **Dùng làm Chat ID quản trị**.
3. Mỗi người muốn nhận cảnh báo đều phải **nhắn cho bot ít nhất một lần** để có Chat ID riêng. Bot chỉ gửi được cho người đã trò chuyện với nó.

### Bước Z4. Lưu và gửi thử

1. Bấm **Lưu cài đặt**, rồi **Gửi tin thử** ở khung Zalo.
2. Muốn một router báo thêm cho người khác: vào **Router → Sửa** và nhập Chat ID Zalo của người đó vào **Chat ID Zalo riêng cho router này**.

Lưu ý về Zalo:

- Mỗi tin Zalo tối đa 2000 ký tự. DrayPulse tự chia và gộp tin cho phù hợp.
- Tài liệu Zalo ghi việc bot hoạt động trong **nhóm** đang ở mức thử nghiệm (Beta). Nên dùng chat cá nhân với bot. Nếu muốn dùng nhóm, hãy thử bằng **Gửi tin thử** trước.
- Nhắn **`status`** cho bot để xem tình trạng mạng.

Có thể bật **cả Telegram và Zalo** cùng lúc: mỗi cảnh báo được gửi tới mọi kênh đã cấu hình.

---

## 6. DrayPulse cảnh báo những gì

| Sự kiện | Ghi vào Sự kiện | Gửi Telegram/Zalo |
|---|---|---|
| Mất / có lại kết nối tới router | ✔ | ✔ |
| WAN mất link / mất Internet / phục hồi | ✔ | ✔ |
| Thiết bị theo dõi mất kết nối / phục hồi | ✔ | ✔ (nếu bật cho thiết bị đó) |
| Router khởi động lại | ✔ | ✔ |
| Firmware DrayOS đổi phiên bản | ✔ | ✔ |
| VLAN bật/tắt hoặc đổi VID/cổng/subnet | ✔ | ✔ |
| DHCP một subnet dùng ≥ 90% địa chỉ | ✔ | ✔ |
| Bảng session NAT của router ≥ 85% | ✔ | ✔ |
| Phát hiện DHCP server lạ trong mạng | ✔ | ✔ |
| Chặn / bỏ chặn IP client (kèm người thực hiện) | ✔ | – |
| VPN kết nối / ngắt, WAN lên/xuống, đăng nhập quản trị (từ syslog) | ✔ | – |
| Thiết bị lạ lần đầu vào mạng | ✔ | tuỳ chọn trong Cài đặt |
| Cổng LAN / WAN mất hoặc có link | ✔ | – |
| IP public của WAN thay đổi | ✔ | – |
| DrayPulse khởi động lại (kèm thời gian gián đoạn) | ✔ | – |

- **Chống báo nhầm:** WAN và thiết bị chỉ bị báo lỗi sau 2 lần kiểm tra liên tiếp thất bại; router chỉ bị báo mất kết nối sau 3 lần.
- **Nhắc lại:** nếu lỗi chưa khắc phục, DrayPulse nhắc lại theo chu kỳ trong Cài đặt (WAN/router) hoặc trong từng thiết bị.
- **Bản tin hằng ngày:** gửi lúc 08:00 (đổi được trong Cài đặt), gồm trạng thái từng router, WAN và thiết bị đang lỗi.
- **Không mất tin:** cảnh báo được ghi vào database trước khi gửi. Khi mất Internet, DrayPulse tự gửi lại khi có mạng (giữ tối đa 24 giờ). Nhiều cảnh báo xảy ra cùng lúc được gộp thành một tin.

Trang **Sự kiện** có ô tìm kiếm và bộ lọc theo mức (Cảnh báo / Thông tin).

---

## 7. Trợ lý AI kiểm tra bảo mật và hiệu suất

Tab **Kiểm tra AI** trong trang router (chỉ quản trị viên chạy được; người xem chỉ đọc báo cáo).

### Cách hoạt động

1. DrayPulse **đọc router một lần, ở chế độ chỉ đọc** qua SNMP và Telnet/SSH: model, firmware và ngày build, trạng thái WAN, VPN đang kết nối, cách quản trị từ Internet (`mngt rmtcfg status`), LAN/DHCP pool, DHCP lease, bảng ARP, cách DrayPulse kết nối (SNMP v2c/v3, Telnet/SSH)… Không có lệnh nào thay đổi router.
2. **Bộ kiểm tra có sẵn** (miễn phí, chạy ngay trên máy DrayPulse) chấm điểm và liệt kê vấn đề kèm cách khắc phục: cho phép quản trị từ Internet, SNMP dùng community mặc định, SNMP v1/v2c không mã hoá, đăng nhập bằng Telnet, firmware DrayOS cũ (đối chiếu ngày build), VPN PPTP, WAN đang bật nhưng mất kết nối, nhiệt độ, CPU/RAM cao kéo dài, WAN chập chờn, thiết bị hay mất kết nối…
3. Nếu bật **trợ lý AI** (Claude, ChatGPT, Gemini, DeepSeek… xem bảng bên dưới), agent tự đọc thêm các mục cần thiết, đối chiếu lịch sử CPU/RAM/lưu lượng/sự kiện trong DrayPulse, loại cảnh báo sai, tìm thêm vấn đề quy tắc bỏ sót. Sau đó agent viết **tổng quan, danh sách vấn đề theo mức độ và cách khắc phục (đường dẫn Web UI DrayTek, lệnh Telnet khi chắc chắn) theo thứ tự an toàn**.

Router chỉ bật SNMP vẫn được kiểm tra, nhưng các mục cần Telnet/SSH (quản trị từ xa, WAN, DHCP) sẽ ghi “không đọc được”. Bật Telnet/SSH để kiểm tra đầy đủ.

### Thêm tài khoản AI

DrayPulse dùng được nhiều nhà cung cấp AI cùng lúc:

| Nhà cung cấp | Lấy API key ở đâu | Ghi chú |
|---|---|---|
| **Claude** (Anthropic) | console.anthropic.com → API Keys | Mặc định Claude Opus 5.5; dùng SDK chính thức, có giá sẵn để ước tính chi phí |
| **ChatGPT** (OpenAI) | platform.openai.com → API keys | Tài khoản API riêng, không phải gói ChatGPT Plus |
| **Gemini** (Google) | aistudio.google.com → Get API key | Có hạn mức miễn phí |
| **DeepSeek** | platform.deepseek.com → API keys | Giá rẻ |
| **Grok** (xAI) | console.x.ai → API Keys | |
| **Mistral** | console.mistral.ai → API Keys | |
| **Groq** | console.groq.com → API Keys | Rất nhanh |
| **OpenRouter** | openrouter.ai → Keys | Một key dùng được hàng trăm mô hình |
| **Qwen** (Alibaba Cloud) | Model Studio → API Key | |
| **Ollama / LM Studio** | không cần key | AI chạy trên máy của bạn; dữ liệu không ra khỏi mạng nội bộ |
| **Khác** | theo nhà cung cấp | Bất kỳ dịch vụ nào tương thích OpenAI Chat Completions |

1. Vào **Cài đặt → Trợ lý AI kiểm tra router → + Thêm tài khoản AI**.
2. Chọn **Nhà cung cấp**. Tên và địa chỉ API được điền sẵn; khung **Cách lấy API key** hiện từng bước cho nhà cung cấp đó, kèm nút **Mở trang lấy key ↗** và lưu ý về chi phí/riêng tư.
3. Dán **API key**, bấm **Kiểm tra & lấy danh sách mô hình**:
   - nếu key sai, DrayPulse báo ngay;
   - nếu đúng, ô **Mô hình** có gợi ý; chọn mô hình mạnh nhất có hỗ trợ gọi công cụ (tools / function calling).
4. (Tuỳ chọn) Nhập **giá đầu vào/đầu ra** (USD cho 1 triệu token) để báo cáo ước tính chi phí. Claude đã có giá sẵn.
5. Bấm **Thêm tài khoản**. Lặp lại cho các tài khoản khác.
6. Chọn tài khoản **Mặc định** bằng nút tròn trong bảng.
7. Đánh dấu **Cho phép gửi cấu hình router…** rồi bấm **Lưu cài đặt**. Nên giữ **Che IP public và MAC** và **Tự chuyển sang tài khoản khác khi lỗi**.

Với **Ollama/LM Studio**, địa chỉ `localhost` là máy đang chạy DrayPulse. Nếu AI chạy ở máy khác trong LAN, đổi thành IP máy đó, ví dụ `http://192.168.1.20:11434/v1`. Mô hình cục bộ nhỏ thường phân tích kém hơn nhiều so với mô hình đám mây.

### Chạy kiểm tra

Mở router → **Kiểm tra AI** → **Chạy kiểm tra**. Nếu có từ hai tài khoản trở lên, ô cạnh nút cho chọn tài khoản cho lần chạy này.

Nếu tài khoản bị lỗi (hết credit, key sai, quá tải) và bạn bật tự chuyển, DrayPulse thử lần lượt các tài khoản khác. Báo cáo ghi rõ đã chuyển vì sao. Kiểm tra định kỳ hằng tuần dùng tài khoản mặc định.

### Dữ liệu gửi đi và chi phí

- **Không bao giờ gửi:** mật khẩu router, community SNMP, mật khẩu SNMPv3. DrayPulse không đọc cấu hình chứa bí mật; chỉ gửi kết quả các lệnh xem (trạng thái WAN, VPN, `mngt rmtcfg status`…) và mọi chuỗi giống mật khẩu đều bị che (`password=***`).
- Khi bật **Che IP public và MAC**, DrayPulse thay các giá trị này bằng mã (`PUBLIC-IP-1`, `MAC-3`) trước khi gửi, rồi đổi lại thành giá trị thật trong báo cáo trên máy bạn.
- Mỗi báo cáo ghi rõ **agent đã xem những mục nào**, số token và **chi phí ước tính** (USD).
- DrayPulse dùng tính năng dự phòng của Anthropic: nếu mô hình chính từ chối một yêu cầu, một mô hình khác sẽ xử lý trong cùng lần gọi.
- Không bật AI thì báo cáo vẫn có đầy đủ phần của bộ kiểm tra có sẵn.

### Đọc báo cáo

- **Điểm Bảo mật** và **Hiệu suất & ổn định** (0–100): từ 80 trở lên là tốt, 50–79 cần xử lý, dưới 50 là rủi ro cao.
- **Vấn đề và cách khắc phục:** sắp xếp theo mức độ, mỗi mục có dữ liệu chứng minh và khối lệnh có nút **Sao chép**.
- **Trước khi sửa Management, Firewall hoặc tài khoản:** sao lưu cấu hình (*System Maintenance → Configuration Backup*) và giữ một phiên quản trị từ LAN. Hầu hết cách khắc phục là đường dẫn trong Web UI; lệnh Telnet chỉ được đưa ra khi chắc chắn có trong DrayOS.
- Ô chọn ở đầu tab cho xem lại các lần kiểm tra trước để so sánh trước và sau khi sửa.

---

## 8. Xử lý sự cố

| Thông báo / hiện tượng | Nguyên nhân | Cách sửa |
|---|---|---|
| Không mở được trang DrayPulse từ máy khác | Tường lửa trên server chặn cổng | Mở cổng (xem mục 1) |
| `router không trả lời SNMP (timeout)` | SNMP chưa bật, sai community/user, hoặc **Manager Host IP** không phải IP DrayPulse | Kiểm tra bước D1; thử `snmpget -v2c -c <community> 192.168.1.1 1.3.6.1.2.1.1.1.0` từ máy DrayPulse |
| `SNMPv3: sai user hoặc mật khẩu…` | Sai user, kiểu xác thực/mã hoá hoặc mật khẩu | Đối chiếu SHA/AES và mật khẩu (8–23 ký tự) |
| `router từ chối Telnet/SSH` | Dịch vụ chưa bật hoặc không cho LAN/IP này | Bước D2; kiểm tra cổng và *LAN Access* |
| `Telnet: sai user hoặc mật khẩu router` | Sai tài khoản, hoặc router đang khoá do đăng nhập sai nhiều lần (Brute Force Protection) | Đăng nhập thử bằng tay, đợi hết thời gian khoá |
| `SSH: …handshake…` | Firmware cũ chỉ có thuật toán SSH đời cũ không tương thích | Cập nhật firmware hoặc dùng Telnet trong LAN |
| Tab Client / DHCP trống | Chưa bật Telnet/SSH | Bật CLI ở bước D2 rồi sửa router trong DrayPulse |
| WAN Internet báo “Lỗi kiểm tra” | Router không chạy được `ip ping` qua WAN đó | Kiểm tra tên WAN (WAN1…), WAN đang bật |
| Tab VLAN trống | Chưa bật Telnet/SSH, hoặc firmware không có lệnh `vlan status` | Bật CLI; DrayOS 5 chưa được hỗ trợ |
| Chặn báo "Bind IP to MAC đang TẮT nhưng bảng có … mục do bạn tạo" | Bảng có mục cũ của bạn, bật lên sẽ áp dụng chúng | Kiểm tra/xoá các mục đó ở LAN → Bind IP to MAC rồi chặn lại |
| Chặn báo "router không lưu mục chặn" | Router từ chối lệnh `ip bindmac add` (firmware khác cú pháp); DrayPulse đã hoàn tác | Báo lại kèm model/firmware |
| Cảnh báo "Đã TẠM DỪNG tự động chặn" | Trong 1 giờ DrayPulse định tự chặn nhiều IP hơn giới hạn (thường do chặn nhầm thiết bị dùng chung hoặc DHCP cấp lại hàng loạt) | Xem tab Client → Client bị chặn, bỏ chặn mục sai (hoặc **Bỏ chặn tất cả**), rồi bấm **Tiếp tục tự động chặn**. Tăng giới hạn ở Cài đặt nếu cần |
| Chặn báo "nằm trong danh sách Không bao giờ chặn" | MAC/IP (hoặc MAC đang dùng IP đó) thuộc danh sách bảo vệ | Bỏ khỏi danh sách ở Cài đặt → Chặn client an toàn nếu thật sự cần chặn |
| Bấm “Chặn” hiện “Đang xử lý…” rất lâu rồi báo lỗi hết thời gian | Phiên Telnet/SSH của router bận liên tục, thường vì nhiều thiết bị được ping **Từ router** | Nâng cấp lên 0.6.3 (lệnh chặn được ưu tiên) và chuyển **Ping thiết bị LAN = Từ máy DrayPulse** nếu máy DrayPulse ping được các thiết bị đó |
| Chặn nhầm nhiều máy cùng lúc | Chặn sai thiết bị, hoặc dữ liệu từ bản cũ (theo tên máy) | Tab Client → **Bỏ chặn tất cả** |
| Client hiện "Ngừng" hàng loạt, sự kiện "DHCP … sắp hết / đã có lại địa chỉ trống" lặp lại; SSH vào router báo "No connection is available now" | Router hết phiên Telnet/SSH. Bản trước 0.6.1 giữ phiên quá lâu rồi mở lại dồn dập làm đầy các phiên (Vigor 3912S/2926 tự đóng phiên rảnh sau khoảng 16–20 giây) | Nâng cấp lên 0.6.1: DrayPulse đăng xuất phiên rảnh sau 10 giây, chờ router trả phiên rồi mới mở lại, và giữ nguyên dữ liệu cũ khi tạm thời không đọc được CLI. Tránh để nhiều công cụ cùng giữ phiên SSH vào router |
| Không thấy dòng nào ở tab Syslog | Router chưa gửi, sai cổng, tường lửa server chặn UDP, hoặc router gửi từ IP khác IP đã khai báo | Xem khung chẩn đoán đầu tab Syslog: cổng đang nghe, các IP gửi chưa gán (bấm **Gán**) |
| WAN báo "Không thấy" | Tên WAN không đúng (phải là WAN1, WAN2…) | Router → Sửa → bấm **Kiểm tra kết nối** và chọn theo gợi ý |
| Telegram/Zalo không nhận tin | Chưa lưu token, sai Chat ID, hoặc chưa nhắn bot trước | Xem lỗi đỏ cạnh tiêu đề kênh trong Cài đặt; nhắn bot rồi **Gửi tin thử** |
| `Bot Token sai hoặc đã bị thu hồi` | Token bị đặt lại | Lấy token mới, dán lại |
| Client hiện "MAC ngẫu nhiên" | Điện thoại/laptop dùng địa chỉ riêng tư | Bấm **Đặt tên** |
| `Trợ lý AI lỗi (…: API key không hợp lệ)` | Sai key hoặc key đã bị thu hồi | Tạo key mới, Sửa tài khoản AI, bấm **Kiểm tra & lấy danh sách mô hình** |
| `… không tìm thấy mô hình hoặc sai địa chỉ API` | Gõ sai tên mô hình hoặc địa chỉ | Chọn lại mô hình từ danh sách |
| Mô hình trả lời nhưng không nộp báo cáo | Mô hình không hỗ trợ gọi công cụ | Chọn mô hình khác (bản lớn/mới hơn) |
| `… vượt giới hạn tần suất hoặc hết hạn mức …` | Hết credit hoặc gọi quá nhiều | Nạp credit ở trang của nhà cung cấp, hoặc bật tự chuyển sang tài khoản khác |
| Báo cáo ghi "không đọc được (cần bật Telnet/SSH…)" | Router chỉ dùng SNMP | Bật Telnet/SSH để kiểm tra quản trị từ xa, WAN, DHCP |
| Quên mật khẩu DrayPulse | – | Dừng DrayPulse, chạy `draypulse reset-password -data <thư mục dữ liệu> admin "MatKhauMoi123"` |

Nếu vẫn không được, xem log của DrayPulse. Với dịch vụ systemd của user:

```bash
systemctl --user status draypulse
```

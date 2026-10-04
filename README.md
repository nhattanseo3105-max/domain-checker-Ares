# 🔍 Domain Checker — Ares

> Công cụ web kiểm tra domain hàng loạt: **nhà đăng ký**, **ngày đăng ký**, **trạng thái hold / chặn transfer**, **nameserver** và **khả năng add vào Cloudflare** — nhanh, gọn, nhiều lớp backup.

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)
![Status](https://img.shields.io/badge/status-active-success)

---

## ✨ Tính năng

| | Tính năng | Mô tả |
|---|---|---|
| 🏢 | **Nhà đăng ký (Registrar)** | Lấy tên registrar từ nhiều nguồn, tự động fallback khi thiếu |
| 📅 | **Ngày đăng ký** | Hiển thị định dạng `dd/mm/yyyy` |
| 🚦 | **Trạng thái domain** | Chỉ báo `serverHold`, `clientHold` và `Chặn Transfer` |
| 🌐 | **Nameserver** | Truy vấn NS qua Google DNS và Cloudflare DNS, nhận biết domain đang dùng Cloudflare |
| ☁️ | **Trạng thái CF** | Thử add domain vào Cloudflare để phát hiện BANNED / bị chặn / TLD bị cấm *(tùy chọn)* |
| 🚫 | **Registry Policy** | Phát hiện domain bị registry cấm đăng ký |
| ⚡ | **Tốc độ cao** | Truy vấn song song, nhiều domain cùng lúc |
| 🔁 | **Retry lỗi** | Một nút để kiểm tra lại các domain bị thiếu dữ liệu |
| 🧹 | **Tự lọc đầu vào** | Dán kèm giá tiền hoặc ký tự lạ vẫn nhận đúng domain |

---

## 🧠 Cách hoạt động

Với mỗi domain, dữ liệu nhà đăng ký / ngày ĐK / trạng thái được lấy theo nhiều lớp:

```
1️⃣  RDAP trực tiếp từ registry (danh sách từ IANA bootstrap)
2️⃣  Theo link "related" sang RDAP của registrar (với registry dạng thin như .com)
3️⃣  rdap.org · rdap.net · who-dat · rdap.cloud   (chạy song song)
4️⃣  WHOIS cổng 43 (python-whois)                 (chỉ khi vẫn thiếu dữ liệu)
```

- Các nguồn ở bước 1–3 chạy **song song**, dừng ngay khi đã đủ dữ liệu.
- Nameserver, WHOIS/RDAP và check CF của cùng một domain cũng chạy song song.
- Nguồn từ registry được ưu tiên hơn các nguồn trung gian.

---

## 🚀 Cài đặt

### Yêu cầu
- Python **3.9+**

### Các bước

```bash
# 1. Cài thư viện
pip install flask requests python-whois

# 2. (Tùy chọn) cấu hình Cloudflare để dùng tính năng check CF
export CF_API_TOKEN="your_cloudflare_api_token"
export CF_ACCOUNT_ID="your_cloudflare_account_id"

# 3. Chạy ứng dụng
python app.py
```

Mở trình duyệt tại 👉 **http://localhost:5000**

---

## ⚙️ Cấu hình

| Biến môi trường | Bắt buộc | Mô tả |
|---|---|---|
| `PORT` | ❌ | Cổng chạy server (mặc định `5000`) |
| `CF_API_TOKEN` | ❌ | API Token Cloudflare, chỉ cần khi bật check CF |
| `CF_ACCOUNT_ID` | ❌ | Account ID Cloudflare, chỉ cần khi bật check CF |

> 🔑 Token Cloudflare cần quyền tạo và xóa Zone. Công cụ sẽ tạo zone thử rồi xóa ngay sau khi kiểm tra.

---

## 🖥️ Hướng dẫn sử dụng

1. 📝 **Dán danh sách domain** vào ô nhập, mỗi dòng một domain. Có thể kèm giá hoặc ghi chú:
   ```
   google.com
   tk88b.net    14,99 USD
   fifasmx.com  12,99 USD
   ```
2. ⚙️ Bấm **Cài đặt** để chọn cột cần kiểm tra (CF, registrar, trạng thái, ngày ĐK, nameserver).
3. 🧵 Chỉnh **Luồng song song** (1–40, mặc định 12).
4. ▶️ Bấm **Bắt đầu kiểm tra** và theo dõi kết quả hiện dần theo thời gian thực.
5. ↻ Bấm **Retry lỗi** để quét lại các domain còn thiếu dữ liệu.

> 💡 **Mẹo:** nếu bị các dịch vụ RDAP/WHOIS giới hạn do kiểm tra quá nhiều, hãy giảm số luồng xuống khoảng 6–8.

---

## 🏷️ Ý nghĩa trạng thái

### Trạng thái domain
| Nhãn | Ý nghĩa |
|---|---|
| 🟢 **Bình thường** | Không bị hold, không khóa transfer |
| 🔴 **serverHold** | Registry giữ domain, không resolve DNS |
| 🔴 **clientHold** | Registrar giữ domain, không resolve DNS |
| 🟡 **Chặn Transfer** | Không chuyển registrar được (client/server transfer prohibited) |
| ⚪ **Chưa đăng ký / Ẩn thông tin** | Domain chưa đăng ký hoặc WHOIS bị ẩn |
| 🔴 **Không thể đăng ký** | Bị Registry Policy cấm |

### Trạng thái Cloudflare
| Nhãn | Ý nghĩa |
|---|---|
| 🟢 **Sạch** | Có thể add vào Cloudflare |
| 🔵 **Sạch (Chưa ĐK)** | Chưa đăng ký, có thể mua |
| 🔴 **BANNED** | Bị Cloudflare cấm thêm |
| 🔴 **Bị CF Chặn Add** | Cloudflare từ chối thêm domain |
| 🟡 **Đuôi TLD bị CF cấm** | TLD không được Cloudflare hỗ trợ |
| ⚪ **Lỗi CF / Không rõ** | Lỗi API hoặc trạng thái không xác định |

---

## 🔌 API

### `POST /api/check`

**Request**
```json
{
  "domain": "example.com",
  "options": {
    "check_cf": false,
    "check_registrar": true,
    "check_hold": true,
    "check_dates": true,
    "check_ns": true
  }
}
```

**Response**
```json
{
  "domain": "example.com",
  "registrar": "RESERVED-Internet Assigned Numbers Authority",
  "status": "<span class='badge badge-warning'>Chặn Transfer</span>",
  "created": "14/08/1995",
  "state": "ok",
  "ns": ["a.iana-servers.net", "b.iana-servers.net"],
  "is_cloudflare": false,
  "cf_add_status": "Bỏ qua"
}
```

`state` nhận một trong các giá trị: `ok` · `unregistered` · `restricted` · `error`.

---

## 🛠️ Công nghệ

- 🐍 **Python / Flask** — backend và giao diện web
- 🌐 **requests** — HTTP với connection pool dùng chung
- 🧵 **ThreadPoolExecutor** — xử lý song song
- 📚 **python-whois** — fallback WHOIS cổng 43
- 🎨 **HTML / CSS / JS thuần** — giao diện dark mode, không cần build

---

## ⚠️ Lưu ý

- Dữ liệu phụ thuộc vào các dịch vụ RDAP/WHOIS công khai; một số registry ẩn thông tin (GDPR) nên có thể không có đủ registrar hoặc ngày ĐK.
- Tính năng check CF tạo rồi xóa zone thật trong tài khoản Cloudflare của bạn, hãy dùng token có phạm vi quyền hợp lý.
- Dùng cho mục đích kiểm tra domain hợp pháp, tuân thủ điều khoản của các dịch vụ bên thứ ba.

---

<p align="center">Made with ❤️ by <b>Ares</b></p>

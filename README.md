<div align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Framework-Flask-green.svg" alt="Framework">
  <img src="https://img.shields.io/badge/License-MIT-purple.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Đang%20phát%20triển-orange.svg" alt="Project Status">
</div>

<h1 align="center">Hệ thống Gửi CV An toàn có Kiểm tra IP</h1>
<p align="center">
  <i>Nền tảng gửi hồ sơ xin việc (CV) bảo mật tuyệt đối với mã hóa đầu-cuối và chữ ký số, đảm bảo chỉ nhà tuyển dụng đích thực mới có thể đọc được hồ sơ của bạn.</i>
</p>

<p align="center">
  <a href="#-tính-năng-nổi-bật">Tính Năng</a> •
  <a href="#-cài-đặt--khởi-động">Cài Đặt</a> •
  <a href="#-luồng-hoạt-động--kiến-trúc">Kiến Trúc Chi Tiết</a>
</p>
<p align="center">
  <a href="#"><strong>🚀 Xem Demo Trực Tuyến (Link Placeholder) 🚀</strong></a>
</p>

## 🌟 Tính Năng Nổi Bật

| Tính Năng | Mô Tả Chi Tiết |
| :--- | :--- |
| 🔐 **Bảo Mật Tối Đa** | Tạo cặp khóa RSA 2048-bit cho từng IP người gửi, mã hóa file bằng AES-256, ký số bằng RSA-PSS để chống giả mạo và đảm bảo tính toàn vẹn. |
| 📁 **Quản Lý CV Thông Minh** | Hỗ trợ tải lên bằng cách kéo-thả, lưu trữ an toàn trên Google Drive, tự động sắp xếp CV theo từng nhà tuyển dụng. |
| 🏢 **Kiểm Soát Truy Cập** | Nhà tuyển dụng phải được phê duyệt mới có thể tham gia hệ thống và nhận CV, mỗi nhà tuyển dụng có khóa giải mã riêng. |
| ⚡ **Cập Nhật Tức Thì** | Sử dụng WebSocket (Socket.IO) để thông báo trạng thái (đã gửi, đã nhận, lỗi...) của CV cho cả hai bên theo thời gian thực. |

---

## 🖼️ Minh Họa Giao Diện & Sơ Đồ Kiến Trúc

### Sơ đồ luồng hoạt động chi tiết
*Sơ đồ mô tả chính xác luồng mã hóa và trao đổi dữ liệu giữa Người gửi, Server và Người nhận.*

![image](https://github.com/user-attachments/assets/e60335a6-1508-42f8-a459-f5dac302124f)



### Giao diện người dùng
*Giao diện tối giản cho phép ứng viên nhập thông tin và tải CV lên một cách nhanh chóng.*

![image](https://github.com/user-attachments/assets/047561a9-44d3-435b-89cf-71f48121e7f7)


## Giao diện người nhận
*Giao diện tối giản cho phép ứng viên nhập thông tin và tải CV lên một cách nhanh chóng.*
![image](https://github.com/user-attachments/assets/d6615e85-5c43-47ee-8ab4-b24d01ddcb68)


## Giao diện người gửi
![image](https://github.com/user-attachments/assets/f17f2561-f805-4555-b47a-36fc60300fcd)

---

## 🛠️ Trình Bày Kỹ Thuật

### Công nghệ sử dụng (Tech Stack)

| Lĩnh vực | Công nghệ | Mục đích |
| :--- | :--- | :--- |
| **Backend** | `Flask`, `Flask-SocketIO`, `SQLAlchemy` | Xây dựng API, xử lý logic và quản lý WebSocket, tương tác CSDL. |
| **Bảo mật** | Thư viện `cryptography` | Implement RSA-2048 (OAEP, PSS), AES-256 (CBC), SHA-512. |
| **Frontend** | `HTML5`, `CSS3`, `Bootstrap 5`, `JavaScript (ES6+)` | Xây dựng giao diện người dùng đáp ứng (responsive). |
| **Lưu trữ** | `Google Drive API v3` & File System | Lưu trữ file CV đã mã hóa một cách linh hoạt và an toàn. |
| **CSDL** | `SQLite` (mặc định), `PostgreSQL` (tùy chọn) | Lưu trữ thông tin về người dùng, file, khóa. |

### Luồng Hoạt Động & Kiến Trúc
Hệ thống đảm bảo an toàn bằng quy trình mã hóa đầu-cuối chi tiết như trong sơ đồ:

1.  **Khởi tạo (Phía Người Gửi):**
    * **Bước 1-2:** Client (Người gửi) gửi yêu cầu "Hello" đến Server. Server phản hồi bằng trạng thái "Ready" và gửi kèm **Khóa Công Khai (Public Key)** của Người nhận.
    * **Bước 3-4:** Client sinh ngẫu nhiên một **Khóa Phiên (Session Key)** và một vector khởi tạo (**IV**) bằng thuật toán `AES`.

2.  **Mã hóa & Ký số tại Client:**
    * **Bước 5:** Nội dung file được mã hóa bằng `AES-256-CBC` sử dụng Session Key và IV vừa tạo. Kết quả thu được là **Ciphertext**.
    * **Bước 6:** Client tính toán giá trị **Hash** của Ciphertext (`SHA-512`).
    * **Bước 7:** Client tạo một gói **Metadata** chứa các thông tin như `filename`, `timestamp`, `sender_id`.
    * **Bước 8:** Client dùng **Khóa Bí Mật (Private Key)** của mình để **ký số** lên gói Metadata, tạo ra **Chữ Ký (Signature)**.
    * **Bước 9:** **Khóa Phiên AES** được mã hóa bằng **Khóa Công Khai** của Người nhận (sử dụng `RSA-OAEP`), tạo ra `encrypted_session_key`.

3.  **Gửi dữ liệu lên Server:**
    * **Bước 10-11:** Client gửi toàn bộ dữ liệu (bao gồm `iv`, `cipher`, `hash`, `signature`, `encrypted_session_key`, `metadata`) lên Server. Server lưu trữ các thông tin này và chờ Người nhận yêu cầu.

4.  **Giải mã & Xác thực (Phía Người Nhận):**
    * **Bước 12-13:** Client (Người nhận) yêu cầu tải file. Server trả về toàn bộ dữ liệu đã lưu.
    * **Bước 14-15:** Người nhận trước hết **kiểm tra Hash** để đảm bảo toàn vẹn file, sau đó dùng **Khóa Công Khai** của Người gửi để **xác thực Chữ Ký**, đảm bảo đúng người gửi.
    * **Bước 16:** Nếu xác thực thành công, Người nhận dùng **Khóa Bí Mật** của mình để giải mã `encrypted_session_key`, lấy lại được **Khóa Phiên AES** ban đầu.
    * **Bước 17-18:** Dùng Khóa Phiên AES và IV để giải mã Ciphertext, khôi phục lại file gốc và hiển thị cho người dùng.
    * **Bước 19-20:** Người nhận gửi thông báo xác nhận (`/verify`) về Server, Server cập nhật trạng thái (`verified/downloaded`).

> ✨ **Kết quả:** Server chỉ đóng vai trò trung gian lưu trữ dữ liệu đã mã hóa mà không thể đọc được nội dung. Chỉ Người gửi và Người nhận hợp lệ mới có thể thực hiện các thao tác mã hóa và giải mã.


## Cấu Trúc Dự Án
```
ANTT/
├── app.py              # Điểm khởi động
├── main.py             # Khởi chạy app
├── routes.py           # API endpoints
├── models.py           # Database models
├── crypto_utils.py     # Hàm mã hóa
├── drive_utils.py      # Google Drive
├── storage_utils.py    # Lưu trữ file
├── events.py           # WebSocket events
├── static/             # Tài nguyên frontend
│   ├── js/
│   └── css/
└── templates/          # HTML templates
```
### Cài Đặt & Khởi Động

#### Yêu Cầu
* Python 3.9+ & Pip
* Node.js (tùy chọn, nếu cần tùy chỉnh frontend)
* Tài khoản Google Cloud với **Google Drive API** đã được bật.

#### Hướng Dẫn Chi Tiết

1.  **Clone dự án về máy:**
    ```bash
    git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
    cd your-repo-name
    ```

2.  **Tạo và kích hoạt môi trường ảo:**
    ```bash
    # Lệnh này tạo một thư mục 'venv' chứa môi trường Python riêng
    python -m venv venv

    # Kích hoạt môi trường trên Windows
    .\venv\Scripts\Activate
    # Kích hoạt môi trường trên macOS/Linux
    source venv/bin/activate
    ```

3.  **Cài đặt các thư viện cần thiết:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Cấu hình Google Drive API:**
    * Truy cập [Google Cloud Console](https://console.cloud.google.com/) và tạo một dự án mới.
    * Vào `APIs & Services > Library`, tìm và bật **Google Drive API**.
    * Vào `APIs & Services > Credentials`, tạo **OAuth 2.0 Client ID**, chọn loại ứng dụng là `Web application`.
    * Sau khi tạo, tải file `client_secret_*.json` về. **Đổi tên file thành `client_secret.json`** và đặt nó ở thư mục gốc của dự án.

5.  **Khởi chạy ứng dụng:**
    ```bash
    python main.py
    ```
    Mở trình duyệt và truy cập `http://127.0.0.1:5000` để bắt đầu.

---


## 📜 Giấy Phép (License)

Dự án này được cấp phép theo Giấy phép MIT. Xem chi tiết tại file `LICENSE.md`.

## 🙏 Lời Cảm Ơn
* Cảm ơn thầy **Trần Đăng Công** đã đưa ra đề tài và hướng dẫn.
* Cảm ơn cộng đồng mã nguồn mở đã cung cấp các công cụ tuyệt vời.

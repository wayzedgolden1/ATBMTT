# ATBMTT
Send_report
📌 Gửi báo cáo công ty qua Server trung gian
Đây là một hệ thống truyền file bảo mật mô phỏng tình huống gửi tài liệu từ công ty đến đối tác thông qua một server trung gian. Hệ thống đảm bảo:

Bảo mật nội dung bằng AES-GCM

Trao đổi khóa an toàn bằng RSA 1024-bit (OAEP)

Xác thực nguồn gốc bằng chữ ký số RSA/SHA-512

Kiểm tra toàn vẹn bằng SHA-512

Ghi log thời gian giao dịch tại server trung gian

Không có kết nối trực tiếp giữa người gửi và người nhận

🧩 Kiến trúc hệ thống

Sender <--> Server trung gian <--> Receiver
          (chỉ chuyển tiếp + log)
          
🛠️ Công nghệ sử dụng
Python 3.10+

Flask – Giao diện web

Socket TCP – Truyền dữ liệu

PyCryptodome – Mã hóa AES/RSA, SHA-512

Base64, JSON – Đóng gói gói tin

🚀 Hướng dẫn chạy chương trình
1. Clone và cài đặt thư viện
bash
Sao chép
Chỉnh sửa
git clone https://github.com/yourusername/report-via-proxy.git
cd report-via-proxy
pip install -r requirements.txt
Yêu cầu thư viện:
pip install pycryptodome flask

2. Sinh khóa RSA

python generate_keys.py

Tạo các file:

sender/sender_private.pem, sender_public.pem

receiver/receiver_private.pem, receiver_public.pem

3. Chạy từng thành phần
Server trung gian:

bash
Sao chép
Chỉnh sửa
python server.py
Receiver (Người nhận):

bash
Sao chép
Chỉnh sửa
cd receiver
python app_receiver.py

Sender (Người gửi):


cd sender
python app_sender.py

4. Cách sử dụng
5. 
Truy cập giao diện người gửi tại http://127.0.0.1:5000

Chọn file .txt bất kỳ (tối đa 10MB)

Gửi file → chờ phản hồi từ người nhận

Trạng thái hiển thị ✅ Thành công hoặc ❌ Lỗi

📂 Cấu trúc thư mục


├── server.py
├── shared.py
├── generate_keys.py
├── sender/
│   ├── app_sender.py
│   ├── sender_private.pem
│   └── sender_public.pem
├── receiver/
│   ├── app_receiver.py
│   ├── receiver_private.pem
│   └── receiver_public.pem
└── static/report.txt (file đã nhận)

✅ Tính năng nổi bật
Mã hóa file an toàn, chống thay đổi và giả mạo

Giao tiếp gián tiếp qua server trung gian

Hệ thống xác thực hai chiều và kiểm tra toàn vẹn

Log rõ ràng thời gian nhận/gửi gói tin


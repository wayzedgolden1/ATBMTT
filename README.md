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

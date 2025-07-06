import socket
import threading
import base64
import json
import os
from flask import Flask, render_template
from Crypto.PublicKey import RSA
from shared import log_event, verify_signature, aes_gcm_decrypt, decrypt_rsa, compute_integrity_hash

# Config
HOST = '127.0.0.1'
PORT = 9003
LOG_FILE = "receiver_log.txt"

app = Flask(__name__)
status = "⏳ Đang chờ tài liệu..."

def safe_log(msg):
    try:
        log_event(LOG_FILE, msg)
    except Exception as e:
        print(f"[Receiver] ❌ Lỗi ghi log: {e}")
    print(f"[Receiver] {msg}")

def receive_full_data(sock, timeout=10):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 4096:
                break
        except socket.timeout:
            break
    return data

def receive_data():
    global status
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()
    safe_log(f"📡 Receiver đang lắng nghe tại {HOST}:{PORT}")

    if not os.path.exists("static"):
        os.makedirs("static")
        safe_log("⚠️ Đã tạo thư mục static để lưu file.")

    while True:
        conn, addr = s.accept()
        try:
            data = receive_full_data(conn)
            if data == b"Hello!":
                safe_log(f"📩 Nhận Handshake 'Hello!' từ {addr}")
                conn.sendall(b"Ready!")
                safe_log("📩 Gửi Handshake 'Ready!'")
                continue

            try:
                pkt = json.loads(data.decode())
            except json.JSONDecodeError:
                safe_log("⚠️ Gói tin không phải JSON")
                conn.sendall(b"NACK: Invalid JSON")
                continue

            try:
                nonce = base64.b64decode(pkt['nonce'])
                cipher = base64.b64decode(pkt['cipher'])
                tag = base64.b64decode(pkt['tag'])
                hash_recv = pkt['hash']
                sig = bytes.fromhex(pkt['sig'])
                encrypted_key = base64.b64decode(pkt['encrypted_key'])
                metadata = pkt['metadata']
                metadata_sig = base64.b64decode(pkt['metadata_sig'])
            except Exception as e:
                safe_log(f"❌ Lỗi phân tích gói JSON: {e}")
                status = "❌ Gói tin không hợp lệ"
                conn.sendall(f"NACK: Invalid packet format - {str(e)}".encode())
                continue

            # Kiểm tra metadata
            if not os.path.exists("sender/sender_public.pem"):
                safe_log("⚠️ Không tìm thấy sender/sender_public.pem")
                conn.sendall(b"NACK: Missing sender public key")
                continue
            with open("sender/sender_public.pem", "rb") as f:
                sender_pubkey = RSA.import_key(f.read())
            metadata_bytes = json.dumps(metadata).encode()
            if not verify_signature(sender_pubkey, metadata_bytes, metadata_sig):
                safe_log("❌ Chữ ký metadata không hợp lệ")
                status = "❌ Chữ ký metadata không hợp lệ"
                conn.sendall(b"NACK: Invalid metadata signature")
                continue

            # Kiểm tra hash
            hash_calc = compute_integrity_hash(nonce, cipher, tag)
            if hash_recv != hash_calc:
                safe_log("❌ Hash toàn vẹn không khớp")
                status = "❌ Dữ liệu bị thay đổi"
                conn.sendall(b"NACK: Integrity hash mismatch")
                continue

            # Kiểm tra chữ ký số
            if not verify_signature(sender_pubkey, hash_recv.encode(), sig):
                safe_log("❌ Chữ ký số không hợp lệ")
                status = "❌ Chữ ký số không hợp lệ"
                conn.sendall(b"NACK: Invalid signature")
                continue

            # Giải mã session key
            if not os.path.exists("receiver/receiver_private.pem"):
                safe_log("⚠️ Không tìm thấy receiver/receiver_private.pem")
                conn.sendall(b"NACK: Missing receiver private key")
                continue
            try:
                with open("receiver/receiver_private.pem", "rb") as f:
                    privkey = RSA.import_key(f.read())
                session_key = decrypt_rsa(privkey, encrypted_key)
            except Exception as e:
                safe_log(f"❌ Lỗi giải mã session key: {e}")
                status = "❌ Lỗi giải mã session key"
                conn.sendall(f"NACK: Session key decryption failed - {str(e)}".encode())
                continue

            # Giải mã file
            try:
                plaintext = aes_gcm_decrypt(session_key, nonce, cipher, tag)
                with open("static/report.txt", "wb") as f:
                    f.write(plaintext)
                safe_log(f"✅ Đã nhận và xác minh thành công file, kích thước: {len(plaintext)} bytes")
                status = f"✅ File đã được xác minh và lưu vào report.txt ({len(plaintext)} bytes)"
                conn.sendall(b"ACK")
            except Exception as e:
                safe_log(f"❌ Lỗi giải mã file: {e}")
                status = "❌ Lỗi giải mã file"
                conn.sendall(f"NACK: Decryption failed - {str(e)}".encode())
        except Exception as e:
            safe_log(f"❌ Lỗi không xác định: {e}")
            conn.sendall(f"NACK: Unknown error - {str(e)}".encode())
        finally:
            conn.close()

@app.route("/")
def index():
    return render_template("index_receiver.html", status=status)

if __name__ == "__main__":
    threading.Thread(target=receive_data, daemon=True).start()
    app.run(port=5003)
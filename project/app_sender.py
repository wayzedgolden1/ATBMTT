import os
import socket
import base64
import json
from datetime import datetime
from flask import Flask, request, render_template
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from shared import log_event, sign_message, aes_gcm_encrypt, compute_integrity_hash, encrypt_rsa, create_metadata

# Config
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9001
LOG_FILE = "sender_log.txt"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

app = Flask(__name__)
status = "🟡 Chưa gửi file"

def safe_log(msg):
    try:
        log_event(LOG_FILE, msg)
    except Exception as e:
        print(f"[Sender] ❌ Lỗi ghi log: {e}")
    print(f"[Sender] {msg}")

def receive_full_data(sock, timeout=15):
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

@app.route("/", methods=["GET", "POST"])
def index():
    global status
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            status = "❌ Không có file được chọn"
            safe_log("Không có file được chọn")
            return render_template("index.html", status=status)

        filename = file.filename
        if not filename.endswith(".txt"):
            status = "❌ Vui lòng chọn file .txt"
            safe_log(f"File không đúng định dạng: {filename}")
            return render_template("index.html", status=status)

        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        if file_size > MAX_FILE_SIZE:
            status = f"❌ File quá lớn (>10MB)"
            safe_log(f"File quá lớn: {file_size} bytes")
            return render_template("index.html", status=status)
        file.seek(0)
        plaintext = file.read()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(b"Hello!")
            response = receive_full_data(s)
            if response != b"Ready!":
                status = "❌ Handshake thất bại"
                safe_log("Handshake thất bại")
                return render_template("index.html", status=status)
            safe_log(f"🤝 Handshake thành công với server, gửi file {filename}")
        except Exception as e:
            status = f"❌ Lỗi kết nối: {e}"
            safe_log(status)
            return render_template("index.html", status=status)
        finally:
            s.close()

        if not os.path.exists("sender/sender_private.pem"):
            status = "⚠️ Thiếu sender_private.pem"
            return render_template("index.html", status=status)

        session_key = get_random_bytes(16)
        nonce = get_random_bytes(12)
        ciphertext, tag = aes_gcm_encrypt(session_key, nonce, plaintext)
        integrity_hash = compute_integrity_hash(nonce, ciphertext, tag)

        with open("sender/sender_private.pem", "rb") as f:
            privkey = RSA.import_key(f.read())
        signature = sign_message(privkey, integrity_hash.encode())

        with open("receiver/receiver_public.pem", "rb") as f:
            receiver_pubkey = RSA.import_key(f.read())
        encrypted_key = encrypt_rsa(receiver_pubkey, session_key)

        metadata, metadata_bytes = create_metadata(filename)
        metadata_signature = sign_message(privkey, metadata_bytes)

        packet = {
            "nonce": base64.b64encode(nonce).decode(),
            "cipher": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode(),
            "hash": integrity_hash,
            "sig": signature.hex(),
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
            "metadata": metadata,
            "metadata_sig": base64.b64encode(metadata_signature).decode()
        }

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(json.dumps(packet).encode())
            response = receive_full_data(s).decode()
            if response.startswith("ACK"):
                status = f"✅ Đã gửi file thành công"
                safe_log(f"Gửi file {filename} thành công")
            else:
                status = f"❌ Gửi thất bại: {response}"
                safe_log(status)
        except Exception as e:
            status = f"❌ Lỗi gửi file: {e}"
            safe_log(status)
        finally:
            s.close()

    return render_template("index.html", status=status)

if __name__ == "__main__":
    app.run(port=5000)

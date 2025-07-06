import socket
import threading
import base64
import json
import os
from flask import Flask, render_template
from Crypto.PublicKey import RSA
from shared import log_event, verify_signature, aes_gcm_decrypt, decrypt_rsa, compute_integrity_hash

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

    while True:
        conn, addr = s.accept()
        try:
            data = receive_full_data(conn)
            if data == b"Hello!":
                conn.sendall(b"Ready!")
                safe_log(f"🤝 Handshake từ {addr} -> Ready!")
                continue

            pkt = json.loads(data.decode())
            nonce = base64.b64decode(pkt['nonce'])
            cipher = base64.b64decode(pkt['cipher'])
            tag = base64.b64decode(pkt['tag'])
            hash_recv = pkt['hash']
            sig = bytes.fromhex(pkt['sig'])
            encrypted_key = base64.b64decode(pkt['encrypted_key'])
            metadata = pkt['metadata']
            metadata_sig = base64.b64decode(pkt['metadata_sig'])

            with open("sender/sender_public.pem", "rb") as f:
                sender_pubkey = RSA.import_key(f.read())
            metadata_bytes = json.dumps(metadata).encode()
            if not verify_signature(sender_pubkey, metadata_bytes, metadata_sig):
                conn.sendall(b"NACK: Invalid metadata signature")
                safe_log("❌ Chữ ký metadata không hợp lệ")
                continue

            hash_calc = compute_integrity_hash(nonce, cipher, tag)
            if hash_recv != hash_calc:
                conn.sendall(b"NACK: Integrity hash mismatch")
                safe_log("❌ Hash toàn vẹn không khớp")
                continue

            if not verify_signature(sender_pubkey, hash_recv.encode(), sig):
                conn.sendall(b"NACK: Invalid signature")
                safe_log("❌ Chữ ký số không hợp lệ")
                continue

            with open("receiver/receiver_private.pem", "rb") as f:
                privkey = RSA.import_key(f.read())
            session_key = decrypt_rsa(privkey, encrypted_key)

            plaintext = aes_gcm_decrypt(session_key, nonce, cipher, tag)
            with open("static/report.txt", "wb") as f:
                f.write(plaintext)
            conn.sendall(b"ACK")
            safe_log(f"✅ Đã nhận và giải mã file thành công ({len(plaintext)} bytes)")
            status = f"✅ Đã lưu report.txt ({len(plaintext)} bytes)"

        except Exception as e:
            conn.sendall(f"NACK: Error - {e}".encode())
            safe_log(f"❌ Lỗi khi xử lý: {e}")
        finally:
            conn.close()

@app.route("/")
def index():
    return render_template("index_receiver.html", status=status)

if __name__ == "__main__":
    threading.Thread(target=receive_data, daemon=True).start()
    app.run(port=5003)

import socket
from shared import log_event

HOST = '127.0.0.1'
PORT = 9001  # Server trung gian duy nhất
RECEIVER_HOST = '127.0.0.1'
RECEIVER_PORT = 9003
LOG_FILE = 'server_log.txt'

def safe_log(msg):
    try:
        log_event(LOG_FILE, msg)
    except Exception as e:
        print(f"[Server] ❌ Lỗi ghi log: {e}")
    print(f"[Server] {msg}")

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

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        safe_log(f"📡 Server trung gian lắng nghe tại {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            try:
                data = receive_full_data(conn)
                if not data:
                    conn.close()
                    continue

                # Log dữ liệu đến
                if data == b"Hello!":
                    safe_log(f"🤝 Nhận Handshake 'Hello!' từ {addr}")
                else:
                    safe_log(f"📦 Nhận gói dữ liệu từ {addr}, kích thước: {len(data)} bytes")

                # Gửi đến Receiver
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward:
                    forward.connect((RECEIVER_HOST, RECEIVER_PORT))
                    forward.sendall(data)
                    safe_log("➡️ Đã chuyển tiếp gói tin đến Receiver")
                    response = receive_full_data(forward)

                # Gửi lại phản hồi cho Sender
                if response:
                    conn.sendall(response)
                    if response == b"ACK":
                        safe_log("✅ Nhận ACK từ Receiver, đã chuyển lại cho Sender")
                    elif response.startswith(b"NACK"):
                        safe_log(f"❌ Nhận NACK từ Receiver: {response.decode()}")
                else:
                    safe_log("⚠️ Không nhận được phản hồi từ Receiver")

            except Exception as e:
                safe_log(f"❌ Lỗi xử lý server: {e}")
            finally:
                conn.close()

if __name__ == "__main__":
    start_server()

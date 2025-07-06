import base64
import hashlib
from datetime import datetime
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import uuid
import json

# Ghi log có hỗ trợ Unicode
def log_event(path: str, msg: str):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now()}] {msg}\n")
    except Exception as e:
        print(f"[LOG ERROR] Không thể ghi log: {e}")

# Ký số bằng RSA + SHA-512
def sign_message(private_key: RSA.RsaKey, message: bytes) -> bytes:
    h = SHA512.new(message)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

# Xác minh chữ ký RSA + SHA-512
def verify_signature(public_key: RSA.RsaKey, message: bytes, signature: bytes) -> bool:
    h = SHA512.new(message)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Mã hóa Session Key bằng RSA (OAEP)
def encrypt_rsa(public_key: RSA.RsaKey, session_key: bytes) -> bytes:
    if len(session_key) != 16:
        raise ValueError("Session key phải là 16 bytes")
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(session_key)

# Giải mã Session Key bằng RSA
def decrypt_rsa(private_key: RSA.RsaKey, encrypted_key: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_key)

# Mã hóa file bằng AES-GCM
def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    if len(nonce) != 12:
        raise ValueError("Nonce phải là 12 bytes")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag

# Giải mã file bằng AES-GCM
def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    if len(nonce) != 12:
        raise ValueError("Nonce phải là 12 bytes")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Tạo và ký metadata
def create_metadata(filename: str) -> tuple[dict, bytes]:
    timestamp = datetime.now().isoformat()
    transaction_id = str(uuid.uuid4())
    metadata = {
        "filename": filename,
        "timestamp": timestamp,
        "transaction_id": transaction_id
    }
    metadata_bytes = json.dumps(metadata).encode()
    return metadata, metadata_bytes

# Tính hash SHA-512(nonce || ciphertext || tag)
def compute_integrity_hash(nonce: bytes, ciphertext: bytes, tag: bytes) -> str:
    return hashlib.sha512(nonce + ciphertext + tag).hexdigest()
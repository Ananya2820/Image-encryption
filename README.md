SCT_CS_01# image_encrypt_aesgcm.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_key():
    # 32 bytes = 256-bit key
    return AESGCM.generate_key(bit_length=256)

def save_key(key: bytes, path: str):
    with open(path, "wb") as f:
        f.write(key)

def load_key(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def encrypt_image(input_path: str, output_path: str, key: bytes):
    aesgcm = AESGCM(key)
    with open(input_path, "rb") as f:
        plaintext = f.read()
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    # Store nonce + ciphertext in file
    with open(output_path, "wb") as f:
        f.write(nonce + ct)
    print(f"Encrypted {input_path} -> {output_path} (nonce prepended)")

def decrypt_image(enc_path: str, out_path: str, key: bytes):
    aesgcm = AESGCM(key)
    with open(enc_path, "rb") as f:
        data = f.read()
    nonce = data[:12]
    ct = data[12:]
    plaintext = aesgcm.decrypt(nonce, ct, associated_data=None)
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"Decrypted {enc_path} -> {out_path}")

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AES-GCM encrypt/decrypt image (key file mode)")
    p.add_argument("mode", choices=["genkey","encrypt","decrypt"])
    p.add_argument("--key

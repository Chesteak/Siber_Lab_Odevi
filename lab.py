import time
import os
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher


def encrypt_image_ecb_ctr(image_path="input.png"):
    img = Image.open(image_path).convert("RGB")
    data = img.tobytes()
    width, height = img.size

    key = os.urandom(16) 

    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)

    cipher_ecb = Cipher(algorithms.AES(key), modes.ECB())
    encryptor_ecb = cipher_ecb.encryptor()
    ecb_encrypted = encryptor_ecb.update(padded_data) + encryptor_ecb.finalize()

    ecb_img = Image.frombytes("RGB", (width, height), ecb_encrypted[:len(data)])
    ecb_img.save("encrypted_ecb.png")

    nonce = os.urandom(16)
    cipher_ctr = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor_ctr = cipher_ctr.encryptor()
    ctr_encrypted = encryptor_ctr.update(data) + encryptor_ctr.finalize()

    ctr_img = Image.frombytes("RGB", (width, height), ctr_encrypted)
    ctr_img.save("encrypted_ctr.png")

    print("[02] Görsel şifreleme tamamlandı (encrypted_ecb.png ve encrypted_ctr.png oluşturuldu).")


def bit_flipping_attack():
    print("\n--- 03. CTR ve AES-GCM Karşılaştırması ---")
    
    key = os.urandom(16)
    nonce = os.urandom(16)

    original_msg = b"Tutar: 100 TL"
    cipher_ctr = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher_ctr.encryptor()
    ciphertext = bytearray(enc.update(original_msg) + enc.finalize())

    old_val = b"100"
    new_val = b"900"
    offset = original_msg.find(old_val)

    for i in range(len(old_val)):
        ciphertext[offset + i] ^= old_val[i] ^ new_val[i]

    cipher_ctr_dec = Cipher(algorithms.AES(key), modes.CTR(nonce))
    dec = cipher_ctr_dec.decryptor()
    tampered_msg = dec.update(bytes(ciphertext)) + dec.finalize()
    print(f"CTR Değiştirilmiş Mesaj: {tampered_msg.decode('utf-8', errors='ignore')}")

    aesgcm = AESGCM(AESGCM.generate_key(bit_length=128))
    gcm_nonce = os.urandom(12)
    gcm_ciphertext = bytearray(aesgcm.encrypt(gcm_nonce, original_msg, None))

    for i in range(len(old_val)):
        gcm_ciphertext[offset + i] ^= old_val[i] ^ new_val[i]

    try:
        aesgcm.decrypt(gcm_nonce, bytes(gcm_ciphertext), None)
    except Exception as e:
        print(f"AES-GCM Sonucu: Değişiklik tespit edildi! Şifre çözülemedi. ({type(e).__name__})")


def benchmark_hashing():
    print("\n--- 04. SHA-256 vs Argon2id Süre Ölçümü ---")
    data = b"GuvenliParola123!"

    start = time.perf_counter()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    digest.finalize()
    sha256_time = time.perf_counter() - start
    print(f"SHA-256 Süresi : {sha256_time:.6f} saniye")

    ph = PasswordHasher()
    start = time.perf_counter()
    ph.hash(data)
    argon2_time = time.perf_counter() - start
    print(f"Argon2id Süresi: {argon2_time:.6f} saniye")


if __name__ == "__main__":
    if not os.path.exists("input.png"):
        test_img = Image.new("RGB", (200, 200), color="white")
        for x in range(50, 150):
            for y in range(50, 150):
                test_img.putpixel((x, y), (0, 0, 0))
        test_img.save("input.png")

    encrypt_image_ecb_ctr("input.png")
    bit_flipping_attack()
    benchmark_hashing()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

BLOCK = 16

def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(8 * BLOCK).padder()
    return padder.update(data) + padder.finalize()

def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(8 * BLOCK).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt_aes128_ecb(key16: bytes, plaintext: bytes) -> bytes:
    assert len(key16) == 16
    cipher = Cipher(algorithms.AES(key16), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()
    return ct

def decrypt_aes128_ecb(key16: bytes, ciphertext: bytes) -> bytes:
    assert len(key16) == 16
    cipher = Cipher(algorithms.AES(key16), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)

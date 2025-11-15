from cryptography.hazmat.primitives.asymmetric import padding as asymp, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def sign_pkcs1v15_sha256(priv_key, data: bytes) -> bytes:
    return priv_key.sign(data, asymp.PKCS1v15(), hashes.SHA256())

def verify_pkcs1v15_sha256(pub_key, signature: bytes, data: bytes) -> bool:
    try:
        pub_key.verify(signature, data, asymp.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def public_from_cert_pem(pem_bytes: bytes):
    cert = x509.load_pem_x509_certificate(pem_bytes)
    return cert.public_key()

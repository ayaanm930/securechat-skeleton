from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymp
from datetime import datetime
import os

CA_CERT_PATH = os.path.join("certs", "ca.cert.pem")

def load_ca_cert(path: str = None):
    path = path or CA_CERT_PATH
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def validate_cert(pem_bytes: bytes, ca_cert=None) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
    except Exception:
        return False
    ca_cert = ca_cert or load_ca_cert()
    # issuer check
    if cert.issuer != ca_cert.subject:
        return False
    # validity period
    now = datetime.utcnow()
    if not (cert.not_valid_before <= now <= cert.not_valid_after):
        return False
    # signature check using CA public key
    try:
        ca_pub = ca_cert.public_key()
        ca_pub.verify(cert.signature, cert.tbs_certificate_bytes, asymp.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

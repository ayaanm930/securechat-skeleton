import os
import warnings
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymp

from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

CA_CERT_PATH = os.path.join("certs", "ca.cert.pem")


def load_ca_cert(path: str = None):
    path = path or CA_CERT_PATH
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _get_not_valid_before(cert: x509.Certificate):
    if hasattr(cert, "not_valid_before_utc"):
        return cert.not_valid_before_utc
    # fallback
    return cert.not_valid_before


def _get_not_valid_after(cert: x509.Certificate):
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc
    return cert.not_valid_after


def validate_cert(pem_bytes: bytes, ca_cert=None) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
    except Exception:
        return False

    ca_cert = ca_cert or load_ca_cert()

    # issuer check
    if cert.issuer != ca_cert.subject:
        return False

    # validity check: choose aware or naive 'now' to match cert properties
    not_before = _get_not_valid_before(cert)
    not_after = _get_not_valid_after(cert)

    if not_before is None or not_after is None:
        return False

    # If cert datetimes are timezone-aware, make 'now' aware in UTC; otherwise use naive utcnow()
    if getattr(not_before, "tzinfo", None) is not None:
        now = datetime.now(timezone.utc)
    else:
        now = datetime.utcnow()

    try:
        if not (not_before <= now <= not_after):
            return False
    except TypeError:
        # fallback: normalize both sides to naive UTC for safety
        try:
            nb = not_before.astimezone(timezone.utc).replace(tzinfo=None)
            na = not_after.astimezone(timezone.utc).replace(tzinfo=None)
            now_naive = datetime.utcnow()
            if not (nb <= now_naive <= na):
                return False
        except Exception:
            return False

    # signature verification using CA public key
    try:
        ca_pub = ca_cert.public_key()
        ca_pub.verify(cert.signature, cert.tbs_certificate_bytes, asymp.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

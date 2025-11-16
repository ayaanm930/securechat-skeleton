import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.crypto.sign import public_from_cert_pem

# Replace with REAL values you copied from the receipt:
TRANSCRIPT_SHA256 = "219394a702916ac61e2f788d5815c5cabb535e34184b6e06f85d1bebbff256d8"
SIG_B64 = "OpD6C+dGUXXNpaZ48ZOg+fW0Qhwgy6uadcfMTEMpJqDu17JhU0QBd0XZyitvewhJYNONO5Xr4lv1QlKLoslveTuCJFICoVIqtzQHS1fuarzB0nedRxKIzMHJTUQRl40kxzF0xTG7W8eanlzLthKIgNiABia3QoDhS0iSdnqcY5WaJiUWfs1N8sze3rjvq063FqmjEnoYgetOzJJ6PH7bXK4HkF+Ca/OaaafNS9lLwNEkZpSxYjwH+pmR7QcZKSIYTn8TJf9FrMHe8pmbeh00M/HsWcIsWMwc9dfs0KStCW6uN8cvXqu2xCvvH9bI4Q+1s+/WyZu0Mxk0mR6YQtlrOw=="

# Load server public key
pub = public_from_cert_pem(open("certs/server.cert.pem","rb").read())

# Convert to bytes
tx_hash = bytes.fromhex(TRANSCRIPT_SHA256)
sig = base64.b64decode(SIG_B64)

try:
    pub.verify(sig, tx_hash, padding.PKCS1v15(), hashes.SHA256())
    print("VALID RECEIPT SIGNATURE ✔")
except Exception as e:
    print("INVALID SIGNATURE ❌")
    print(e)

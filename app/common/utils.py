import base64, hashlib, time
from typing import Union

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

def now_ms() -> int:
    return int(time.time() * 1000)

def sha256_hex(data: Union[bytes, str]) -> str:
    if isinstance(data, str): data = data.encode()
    return hashlib.sha256(data).hexdigest()

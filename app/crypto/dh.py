# app/crypto/dh.py
import os, hashlib

# Use a 2048-bit safe prime (RFC 3526-like). For assignment/testing use fixed prime.
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B5766"
    "25E7EC6F44C42E9A63A36210000000000090563"
)
P = int(P_HEX, 16)
G = 2

def generate_private(num_bytes: int = 32) -> int:
    return int.from_bytes(os.urandom(num_bytes), "big")

def public_from_private(priv: int, g: int = G, p: int = P) -> int:
    return pow(g, priv, p)

def shared_secret(their_pub: int, my_priv: int, p: int = P) -> int:
    return pow(their_pub, my_priv, p)

def derive_session_key_from_ks(ks_int: int) -> bytes:
    be = ks_int.to_bytes((ks_int.bit_length() + 7)//8 or 1, "big")
    h = hashlib.sha256(be).digest()
    return h[:16]  # AES-128 key

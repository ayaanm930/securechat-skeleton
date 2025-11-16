import socket
import json
import base64
import os
import hashlib
import time
import traceback

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.common.utils import b64e, now_ms
from app.crypto.pki import validate_cert
from app.crypto.dh import generate_private, public_from_private, shared_secret, derive_session_key_from_ks, P, G
from app.crypto.aes import encrypt_aes128_ecb, decrypt_aes128_ecb
from app.crypto.sign import load_private_key, public_from_cert_pem
from app.storage import db as store

CERT_DIR = "certs"
CLIENT_CERT = os.path.join(CERT_DIR, "client.cert.pem")
CLIENT_KEY = os.path.join(CERT_DIR, "client.key.pem")
SERVER_CERT = os.path.join(CERT_DIR, "server.cert.pem")



#TESTING FLAGS
TEST_REPLAY = False  # <--- set to True only during test
TEST_SIG_FAIL = False   # <--- set to True only during test

def send_frame(conn, obj):
    raw = json.dumps(obj).encode()
    conn.sendall(len(raw).to_bytes(4, "big") + raw)

def recv_frame(conn):
    ln = conn.recv(4)
    if not ln:
        return None
    size = int.from_bytes(ln, "big")
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return json.loads(data.decode())

def client_flow(server_host="127.0.0.1", server_port=9000):
    s = socket.socket()
    try:
        s.connect((server_host, server_port))
    except Exception as e:
        print("connect failed:", e); return

    client_cert_pem = open(CLIENT_CERT, "rb").read().decode()
    nonce = b64e(os.urandom(16))
    send_frame(s, {"type":"hello", "cert_pem": client_cert_pem, "nonce_b64": nonce})

    sh = recv_frame(s)
    if not sh or sh.get("type") != "server_hello":
        print("bad server hello", sh); s.close(); return

    server_cert_pem = sh.get("cert_pem")
    if not server_cert_pem:
        print("server hello missing cert"); s.close(); return

    # verify server cert
    if not validate_cert(server_cert_pem.encode()):
        print("server cert invalid"); s.close(); return

    #initial DH
    a = generate_private(); A = public_from_private(a)
    send_frame(s, {"type":"dh_client", "g": str(G), "p": str(P), "A": str(A)})
    srv = recv_frame(s)
    if not srv or srv.get("type") != "dh_server":
        print("DH server missing", srv); s.close(); return
    B = int(srv["B"])
    Ks = shared_secret(B, a)
    session_key = derive_session_key_from_ks(Ks)

    choice = input("Register (r) or Login (l)? ").strip().lower()
    if choice == "r":
        email = input("email> ").strip()
        username = input("username> ").strip()
        pwd = input("password> ").encode()
        salt = os.urandom(16)
        h = hashlib.sha256(salt + pwd).digest()
        payload = {"type":"register", "email": email, "username": username,
                   "salt": base64.b64encode(salt).decode(), "pwd": base64.b64encode(h).decode()}
        enc = encrypt_aes128_ecb(session_key, json.dumps(payload).encode())
        send_frame(s, {"payload_b64": base64.b64encode(enc).decode()})
        resp = recv_frame(s)
        print("server:", resp)
        s.close(); print("registration done; restart client to login"); return

    #LOGIN flow (challenge-response)
    email = input("email> ").strip()
    pwd = input("password> ").encode()
    payload = {"type":"login_request", "email": email}
    enc = encrypt_aes128_ecb(session_key, json.dumps(payload).encode())
    send_frame(s, {"payload_b64": base64.b64encode(enc).decode()})

    challenge = recv_frame(s)
    if not challenge or challenge.get("type") != "login_challenge":
        print("server:", challenge); s.close(); return
    salt = base64.b64decode(challenge["salt_b64"])
    h = hashlib.sha256(salt + pwd).digest()
    final = {"type":"login_final", "pwd_hash_b64": base64.b64encode(h).decode()}
    enc2 = encrypt_aes128_ecb(session_key, json.dumps(final).encode())
    send_frame(s, {"payload_b64": base64.b64encode(enc2).decode()})
    resp2 = recv_frame(s)
    print("server:", resp2)
    if not resp2 or resp2.get("type") == "err":
        s.close(); return

    #post-auth DH for chat
    a2 = generate_private(); A2 = public_from_private(a2)
    send_frame(s, {"type":"dh_client", "g": str(G), "p": str(P), "A": str(A2)})
    srv2 = recv_frame(s)
    if not srv2 or srv2.get("type") != "dh_server":
        print("missing DH2", srv2); s.close(); return
    B2 = int(srv2["B"])
    Ks2 = shared_secret(B2, a2)
    chat_key = derive_session_key_from_ks(Ks2)
    ready = recv_frame(s)
    print("server:", ready)

    client_priv = load_private_key(CLIENT_KEY)
    seq = 1
    try:
        while True:
            txt = input("msg> ")
            if txt.strip() == "/end":
                try:
                    send_frame(s, {"type":"end"})
                    receipt = recv_frame(s)
                    print("receipt:", receipt)
                except Exception:
                    pass
                break

            ts = now_ms()
            ct = encrypt_aes128_ecb(chat_key, txt.encode())
            orig_ct = ct[:]

            concat = str(seq).encode() + str(ts).encode() + orig_ct
            hmsg = hashlib.sha256(concat).digest()
            try:
                sig = base64.b64encode(client_priv.sign(hmsg, padding.PKCS1v15(), hashes.SHA256())).decode()

                #SIG_FAIL → tamper AFTER signing
                if TEST_SIG_FAIL:
                    ct = bytearray(ct)
                    ct[0] ^= 0x01      # flip 1 bit
                    ct = bytes(ct)

                ct_b64 = base64.b64encode(ct).decode()

            except Exception as e:
                print("sign failed:", e); break
            send_frame(s, {"type":"msg","seqno": seq, "ts": ts, "ct_b64": ct_b64, "sig_b64": sig})

            reply = recv_frame(s)
            print("reply:", reply)
            
            if TEST_REPLAY: #REPLAY → resend previous message with same seq no.
                if seq > 1:
                    seq = 1
            else:
                seq += 2


    except KeyboardInterrupt:
        print("Interrupted by user")
    except Exception as e:
        print("client error:", e)
        traceback.print_exc()
    finally:
        try: s.close()
        except: pass

if __name__ == "__main__":
    client_flow()

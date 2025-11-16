import socket
import threading
import json
import base64
import time
import os
import hashlib
import traceback

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.common.utils import b64e, now_ms, sha256_hex
from app.crypto.pki import validate_cert
from app.crypto.dh import generate_private, public_from_private, shared_secret, derive_session_key_from_ks, P, G
from app.crypto.aes import encrypt_aes128_ecb, decrypt_aes128_ecb
from app.crypto.sign import load_private_key, public_from_cert_pem, verify_pkcs1v15_sha256
from app.storage import db as store
from app.storage.transcript import append_lines, sha256_of_file

CERT_DIR = "certs"
SERVER_CERT = os.path.join(CERT_DIR, "server.cert.pem")
SERVER_KEY = os.path.join(CERT_DIR, "server.key.pem")

SHUTDOWN = False
def admin_shutdown_listener():
    global SHUTDOWN
    while True:
        cmd = input().strip().lower()
        if cmd == "shutdown":
            print("Shutting down server...")
            SHUTDOWN = True
            break

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

def safe_sign(priv_key, data: bytes):
    return priv_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

def handle_client(conn, addr):
    try:
        hello = recv_frame(conn)
        if not hello or hello.get("type") != "hello":
            send_frame(conn, {"type":"err","err":"expected hello"})
            conn.close(); return

        client_cert_pem = hello.get("cert_pem")
        if not client_cert_pem:
            send_frame(conn, {"type":"err","err":"missing cert"}); conn.close(); return

        if not validate_cert(client_cert_pem.encode()):
            send_frame(conn, {"type":"err","err":"bad_cert"}); conn.close(); return

        server_cert_pem = open(SERVER_CERT, "rb").read().decode()
        server_nonce = b64e(os.urandom(16))
        send_frame(conn, {"type":"server_hello","cert_pem": server_cert_pem, "nonce_b64": server_nonce})

        dhc = recv_frame(conn)
        if not dhc or dhc.get("type") != "dh_client":
            send_frame(conn, {"type":"err","err":"expected dh_client"}); conn.close(); return
        g = int(dhc["g"]); p = int(dhc["p"]); A = int(dhc["A"])
        b = generate_private()
        B = public_from_private(b, g, p)
        send_frame(conn, {"type":"dh_server", "B": str(B)})
        Ks = shared_secret(A, b, p)
        session_key = derive_session_key_from_ks(Ks)

        payload_frame = recv_frame(conn)
        if not payload_frame or "payload_b64" not in payload_frame:
            send_frame(conn, {"type":"err","err":"missing_payload"}); conn.close(); return
        try:
            enc = base64.b64decode(payload_frame["payload_b64"])
            plaintext = decrypt_aes128_ecb(session_key, enc)
            data = json.loads(plaintext.decode())
        except Exception:
            send_frame(conn, {"type":"err","err":"aes_decrypt_fail"}); conn.close(); return

        if data.get("type") == "register":
            try:
                email = data["email"]; username = data["username"]
                salt = base64.b64decode(data["salt"])
                pwd_hash_hex = base64.b64decode(data["pwd"]).hex()
            except Exception:
                send_frame(conn, {"type":"err","err":"bad_register_format"}); conn.close(); return
            ok = store.insert_user(email, username, salt, pwd_hash_hex)
            if ok:
                send_frame(conn, {"type":"ok","msg":"registered"})
            else:
                send_frame(conn, {"type":"err","err":"exists"})
            conn.close(); return

        elif data.get("type") == "login_request":
            email = data.get("email")
            user = store.get_user_by_email(email)
            if not user:
                send_frame(conn, {"type":"err","err":"no_user"}); conn.close(); return

            send_frame(conn, {"type":"login_challenge", "salt_b64": base64.b64encode(user["salt"]).decode()})

            payload2 = recv_frame(conn)
            if not payload2 or "payload_b64" not in payload2:
                send_frame(conn, {"type":"err","err":"login_final_missing"}); conn.close(); return
            try:
                enc2 = base64.b64decode(payload2["payload_b64"])
                plain2 = decrypt_aes128_ecb(session_key, enc2)
                data2 = json.loads(plain2.decode())
            except Exception:
                send_frame(conn, {"type":"err","err":"aes_decrypt_fail2"}); conn.close(); return

            if data2.get("type") != "login_final" or "pwd_hash_b64" not in data2:
                send_frame(conn, {"type":"err","err":"bad_login_final"}); conn.close(); return

            client_hash_hex = base64.b64decode(data2["pwd_hash_b64"]).hex()
            if client_hash_hex != user["pwd_hash"]:
                send_frame(conn, {"type":"err","err":"bad_creds"}); conn.close(); return

            send_frame(conn, {"type":"ok","msg":"login_ok"})

        else:
            send_frame(conn, {"type":"err","err":"unknown_action"}); conn.close(); return

        dh2 = recv_frame(conn)
        if not dh2 or dh2.get("type") != "dh_client":
            send_frame(conn, {"type":"err","err":"expected dh_client_2"}); conn.close(); return
        g2 = int(dh2["g"]); p2 = int(dh2["p"]); A2 = int(dh2["A"])
        b2 = generate_private()
        B2 = public_from_private(b2, g2, p2)
        send_frame(conn, {"type":"dh_server", "B": str(B2)})
        Ks2 = shared_secret(A2, b2, p2)
        chat_key = derive_session_key_from_ks(Ks2)

        priv = load_private_key(SERVER_KEY)
        client_pub = public_from_cert_pem(client_cert_pem.encode())

        send_frame(conn, {"type":"ready","msg":"chat_ready"})

        transcript_lines = []
        last_seq = 0

        while True:
            frm = recv_frame(conn)
            if not frm:
                break

            if frm.get("type") == "msg":
                try:
                    seq = int(frm["seqno"]); ts = int(frm["ts"]); ct_b64 = frm["ct_b64"]; sig_b64 = frm["sig_b64"]
                except Exception:
                    send_frame(conn, {"type":"err","err":"bad_msg_format"}); continue

                if seq <= last_seq:
                    send_frame(conn, {"type":"err","err":"replay"}); continue

                concat = str(seq).encode() + str(ts).encode() + base64.b64decode(ct_b64)
                h = hashlib.sha256(concat).digest()
                sig = base64.b64decode(sig_b64)
                if not verify_pkcs1v15_sha256(client_pub, sig, h):
                    send_frame(conn, {"type":"err","err":"sig_fail"}); continue

                try:
                    plaintext = decrypt_aes128_ecb(chat_key, base64.b64decode(ct_b64))
                except Exception:
                    send_frame(conn, {"type":"err","err":"decrypt_fail"}); continue

                print(f"[client {addr}] seq={seq} -> {plaintext.decode(errors='replace')}")
                peer_fp = sha256_hex(client_cert_pem.encode())
                transcript_lines.append(f"{seq}|{ts}|{ct_b64}|{sig_b64}|{peer_fp}")
                last_seq = seq

                reply_text = f"ACK {seq}"
                reply_seq = seq + 1
                reply_ts = now_ms()
                reply_ct = encrypt_aes128_ecb(chat_key, reply_text.encode())
                reply_ct_b64 = base64.b64encode(reply_ct).decode()
                concat2 = str(reply_seq).encode() + str(reply_ts).encode() + base64.b64decode(reply_ct_b64)
                h2 = hashlib.sha256(concat2).digest()
                sig2 = base64.b64encode(safe_sign(priv, h2)).decode()
                send_frame(conn, {"type":"msg","seqno":reply_seq,"ts":reply_ts,"ct_b64":reply_ct_b64,"sig_b64":sig2})
                transcript_lines.append(f"{reply_seq}|{reply_ts}|{reply_ct_b64}|{sig2}|{sha256_hex(open(SERVER_CERT,'rb').read())}")

            elif frm.get("type") == "end":
                path = append_lines(transcript_lines)
                tx_hash = sha256_of_file(path)
                try:
                    sig_tx = base64.b64encode(safe_sign(priv, bytes.fromhex(tx_hash))).decode()
                except Exception:
                    sig_tx = ""
                receipt = {
                    "type":"receipt",
                    "first_seq": int(transcript_lines[0].split("|")[0]) if transcript_lines else 0,
                    "last_seq": int(transcript_lines[-1].split("|")[0]) if transcript_lines else 0,
                    "transcript_sha256": tx_hash,
                    "sig_b64": sig_tx
                }
                send_frame(conn, receipt)
                conn.close(); return

            else:
                send_frame(conn, {"type":"err","err":"unknown_frame"})
    except Exception as e:
        print("connection handler error:", e)
        traceback.print_exc()
    finally:
        try:
            conn.close()
        except Exception:
            pass

def start_server(host="0.0.0.0", port=9000):
    store.ensure_schema()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(8)
    print("Server listening on", host, port)

    global SHUTDOWN
    while not SHUTDOWN:
        try:
            s.settimeout(1.0)        
            conn, addr = s.accept()
        except socket.timeout:
            continue
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

    s.close()
    print("Server stopped cleanly.")

if __name__ == "__main__":
    threading.Thread(target=admin_shutdown_listener, daemon=True).start()
    start_server()

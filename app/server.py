import socket, threading, json, base64, time, os, hashlib
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app.common.utils import b64e, b64d, now_ms, sha256_hex
from app.common.protocol import Hello, ServerHello, DHClient, DHServer, EncryptedPayload, Message, End, Receipt
from app.crypto.pki import validate_cert
from app.crypto.dh import generate_private, public_from_private, shared_secret, derive_session_key_from_ks, P, G
from app.crypto.aes import encrypt_aes128_ecb, decrypt_aes128_ecb
from app.crypto.sign import load_private_key, public_from_cert_pem, verify_pkcs1v15_sha256
from app.storage import db as store
from app.storage.transcript import append_lines, sha256_of_file

CERT_DIR = "certs"
SERVER_CERT = os.path.join(CERT_DIR, "server.cert.pem")
SERVER_KEY = os.path.join(CERT_DIR, "server.key.pem")

def send_frame(conn, obj):
    raw = json.dumps(obj).encode()
    conn.sendall(len(raw).to_bytes(4,"big")+raw)

def recv_frame(conn):
    ln = conn.recv(4)
    if not ln: return None
    size = int.from_bytes(ln,"big")
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk: break
        data += chunk
    return json.loads(data.decode())

def handle_client(conn, addr):
    try:
        hello = recv_frame(conn)
        if not hello or hello.get("type") != "hello":
            send_frame(conn, {"type":"err","err":"expected hello"}); conn.close(); return
        client_cert_pem = hello["cert_pem"].encode()
        nonce_b64 = hello["nonce_b64"]
        if not validate_cert(client_cert_pem):
            send_frame(conn, {"type":"err","err":"bad_cert"}); conn.close(); return
        server_cert_pem = open(SERVER_CERT,"rb").read().decode()
        server_nonce = b64e(os.urandom(16))
        send_frame(conn, {"type":"server_hello","cert_pem": server_cert_pem, "nonce_b64": server_nonce})

        # initial DH
        dhc = recv_frame(conn)
        if not dhc or dhc.get("type")!="dh_client":
            send_frame(conn, {"type":"err","err":"expected dh_client"}); conn.close(); return
        g = int(dhc["g"]); p = int(dhc["p"]); A = int(dhc["A"])
        b = generate_private()
        B = public_from_private(b, g, p)
        send_frame(conn, {"type":"dh_server","B": str(B)})
        Ks = shared_secret(A, b, p)
        session_key = derive_session_key_from_ks(Ks)  # 16 bytes

        # receive encrypted registration/login payload
        payload_frame = recv_frame(conn)
        if not payload_frame or "payload_b64" not in payload_frame:
            send_frame(conn, {"type":"err","err":"missing_payload"}); conn.close(); return
        enc = base64.b64decode(payload_frame["payload_b64"])
        try:
            plaintext = decrypt_aes128_ecb(session_key, enc)
        except Exception:
            send_frame(conn, {"type":"err","err":"aes_decrypt_fail"}); conn.close(); return
        data = json.loads(plaintext.decode())
        # registration
        if data.get("type") == "register":
            email = data["email"]; username = data["username"]
            salt_b64 = data["salt"]; pwd_b64 = data["pwd"]
            salt = base64.b64decode(salt_b64)
            pwd_hash_hex = base64.b64decode(pwd_b64).hex()  # store hex string
            ok = store.insert_user(email, username, salt, pwd_hash_hex)
            if ok:
                send_frame(conn, {"type":"ok","msg":"registered"})
            else:
                send_frame(conn, {"type":"err","err":"exists"})
            conn.close(); return
        elif data.get("type") == "login":
            email = data["email"]
            client_pwd_hash_hex = base64.b64decode(data["pwd"]).hex()
            user = store.get_user_by_email(email)
            if not user:
                send_frame(conn, {"type":"err","err":"no_user"}); conn.close(); return
            if user["pwd_hash"] != client_pwd_hash_hex:
                send_frame(conn, {"type":"err","err":"bad_creds"}); conn.close(); return
            send_frame(conn, {"type":"ok","msg":"login_ok"})
        else:
            send_frame(conn, {"type":"err","err":"unknown_action"}); conn.close(); return

        # post-auth DH for chat
        dhc2 = recv_frame(conn)
        if not dhc2 or dhc2.get("type")!="dh_client":
            send_frame(conn, {"type":"err","err":"expected dh_client2"}); conn.close(); return
        g2 = int(dhc2["g"]); p2 = int(dhc2["p"]); A2 = int(dhc2["A"])
        b2 = generate_private(); B2 = public_from_private(b2, g2, p2)
        send_frame(conn, {"type":"dh_server","B": str(B2)})
        Ks2 = shared_secret(A2, b2, p2)
        chat_key = derive_session_key_from_ks(Ks2)

        # prepare signing key and client pubkey
        priv = load_private_key(SERVER_KEY)
        client_pub = public_from_cert_pem(client_cert_pem)

        send_frame(conn, {"type":"ready","msg":"chat_ready"})
        transcript_lines = []
        last_seq = 0
        while True:
            frm = recv_frame(conn)
            if not frm: break
            if frm.get("type") == "msg":
                seq = int(frm["seqno"]); ts = int(frm["ts"]); ct_b64 = frm["ct_b64"]; sig_b64 = frm["sig_b64"]
                if seq <= last_seq:
                    send_frame(conn, {"type":"err","err":"replay"}); continue
                concat = str(seq).encode() + str(ts).encode() + base64.b64decode(ct_b64)
                h = hashlib.sha256(concat).digest()
                sig = base64.b64decode(sig_b64)
                if not verify_pkcs1v15_sha256(client_pub, sig, h):
                    send_frame(conn, {"type":"err","err":"sig_fail"}); continue
                # decrypt
                try:
                    pt = decrypt_aes128_ecb(chat_key, base64.b64decode(ct_b64))
                except Exception:
                    send_frame(conn, {"type":"err","err":"decrypt_fail"}); continue
                print(f"CLIENT[{seq}]:", pt.decode())
                peer_fp = sha256_hex(client_cert_pem)
                transcript_lines.append(f"{seq}|{ts}|{ct_b64}|{sig_b64}|{peer_fp}")
                last_seq = seq
                # reply
                rtxt = f"ACK {seq}"
                rseq = seq + 1
                rts = now_ms()
                rct = encrypt_aes128_ecb(chat_key, rtxt.encode())
                rct_b64 = base64.b64encode(rct).decode()
                concat2 = str(rseq).encode() + str(rts).encode() + base64.b64decode(rct_b64)
                h2 = hashlib.sha256(concat2).digest()
                sig2 = base64.b64encode(priv.sign(h2, __import__("cryptography.hazmat.primitives.asymmetric.padding").PKCS1v15(), __import__("cryptography.hazmat.primitives.hashes").SHA256())).decode()
                send_frame(conn, {"type":"msg","seqno":rseq,"ts":rts,"ct_b64":rct_b64,"sig_b64":sig2})
                transcript_lines.append(f"{rseq}|{rts}|{rct_b64}|{sig2}|{sha256_hex(open(SERVER_CERT,'rb').read())}")
            elif frm.get("type") == "end":
                path = append_lines(transcript_lines)
                tx_hash = sha256_of_file(path)
                sig_tx = base64.b64encode(priv.sign(bytes.fromhex(tx_hash), __import__("cryptography.hazmat.primitives.asymmetric.padding").PKCS1v15(), __import__("cryptography.hazmat.primitives.hashes").SHA256())).decode()
                receipt = {"type":"receipt","first_seq": int(transcript_lines[0].split("|")[0]) if transcript_lines else 0,
                           "last_seq": int(transcript_lines[-1].split("|")[0]) if transcript_lines else 0,
                           "transcript_sha256": tx_hash, "sig_b64": sig_tx}
                send_frame(conn, receipt)
                conn.close(); return
            else:
                send_frame(conn, {"type":"err","err":"unknown_frame"})
    except Exception as e:
        print("conn handler error:", e)
    finally:
        try: conn.close()
        except: pass

def start_server(host="0.0.0.0", port=9000):
    store.ensure_schema()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print("Server listening on", host, port)
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

if __name__ == "__main__":
    start_server()

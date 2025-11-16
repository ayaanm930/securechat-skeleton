# SecureChat — Assignment #2 (CS-3002 Information Security, Fall 2025)
# by Ayaan Mughal (22i-0861)
# CS-K

A console-based **PKI-enabled Secure Chat System** implemented using **application-layer cryptography only** (NO TLS/SSL).  
Implements **Confidentiality, Integrity, Authenticity, and Non-Repudiation** using AES, RSA signatures, DH key exchange, and X.509 certificate validation.

This README includes **full setup, execution, testing, and evidence procedures** exactly as required for Assignment #2.

---

## 🔗 GitHub Repository
👉 **Your fork URL:** `https://github.com/ayaanm930/securechat-skeleton.git`

---

# 📦 Project Overview

### **✔ Confidentiality**
AES-128-ECB + PKCS#7 padding (base64-encoded ciphertext in all protocol frames).

### **✔ Integrity & Authenticity**
RSA-2048 PKCS#1 v1.5 signatures using SHA-256.

### **✔ Forward Secrecy**
Diffie-Hellman 2048-bit ephemeral key exchange → AES session key.

### **✔ Authentication**
X.509 client/server certificates signed by CA.

### **✔ Non-Repudiation**
Append-only transcript + signed `SessionReceipt` containing transcript SHA-256.

Everything is performed **explicitly at the application layer**.

---

# 📂 Folder Structure (Simplified)

```

app/
client.py
server.py
crypto/
aes.py
dh.py
pki.py
sign.py
common/
protocol.py
utils.py
storage/
db.py
transcript.py

scripts/
gen_ca.py
gen_cert.py

tests/
manual/NOTES.md
transcript_test.py

certs/
transcripts/

````

---

# ⚙️ Environment Setup

## 1. Create Virtual Environment & Install Requirements

### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
````

### Windows PowerShell

```powershell
python -m venv .venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

---

# 🗄️ MySQL Setup (via Docker)

### Run MySQL:

```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

### Ensure `.env` contains:

```
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=scuser
MYSQL_PASS=scpass
MYSQL_DB=securechat
```

### Create database tables (automatically done on server start)

If required manually:

```bash
python -c "from app.storage.db import ensure_schema; ensure_schema()"
```

---

# 🔐 Certificate Generation

All certificate creation must be done **locally**.
**Never commit private keys.**

### Generate Root CA:

```bash
python scripts/gen_ca.py
```

### Generate Server Certificate:

```bash
python scripts/gen_cert.py server
```

### Generate Client Certificate:

```bash
python scripts/gen_cert.py client
```

You will get:

```
certs/ca.cert.pem
certs/ca.key.pem            (DO NOT COMMIT)
certs/server.cert.pem
certs/server.key.pem        (DO NOT COMMIT)
certs/client.cert.pem
certs/client.key.pem        (DO NOT COMMIT)
```

---

# 🚀 Running Server & Client

## 1. Start Server

```bash
python app/server.py
```

Default: `0.0.0.0:9000`

## 2. Start Client (New Terminal)

```bash
python app/client.py
```

---

# 🧑‍💻 Client Workflow (Register → Login → Chat)

### Register

```
Register (r) or Login (l)? r
email> alice@mail.com
username> alice
password> mypass123
server: {"type": "ok", "msg": "registered"}
```

Restart client → login.

### Login

```
Register (r) or Login (l)? l
email> alice@mail.com
password> mypass123
server: {"type": "ok", "msg": "login_ok"}
server: {"type": "ready", "msg": "chat_ready"}
```

### Chat Mode

```
msg> hello
reply: {...encrypted...}
msg> second msg
msg> /end
receipt: { ...SessionReceipt... }
```

ALL messages after auth are encrypted + signed.

---

# 🧪 Manual Testing Requirements

* ✔ Encrypted payloads only (Wireshark)
* ✔ `BAD_CERT` on invalid/self-signed cert
* ✔ `SIG_FAIL` when ciphertext is tampered
* ✔ `REPLAY` on reused sequence number
* ✔ Signed `SessionReceipt` + transcript hash verification

Below are exact reproduction steps.

---

# 📡 Test 1 — Encrypted Payloads (Wireshark)

Start capture BEFORE running client:

### Linux:

```bash
sudo tcpdump -i lo -s 0 -w securechat.pcap port 9000
```

### Windows:

Use Wireshark
Filter:

```
tcp.port == 9000
```

It must show:

* No plaintext JSON fields containing the message body
* Only ciphertext field `ct_b64`

---

# 🚫 Test 2 — BAD_CERT (Invalid Certificate)

Replace client certificate with garbage:

```powershell
mv certs/client.cert.pem certs/client.cert.pem.bak
echo "garbage" > certs/client.cert.pem
python app/client.py
```

Client should receive:

```
{"type":"err","err":"bad_cert"}
```

Server logs show validation failure.

Restore file afterward.

---

# 🧪 Test 3 — SIG_FAIL (Tamper Detection)

Temporary testing toggle:

Add in `client.py`:

```python
TEST_SIG_FAIL = True
```

After computing signature but before sending:

```python
if TEST_SIG_FAIL:
    ct = bytearray(ct)
    ct[0] ^= 0x01     # flip 1 bit
    ct = bytes(ct)
```

Run client → send one message.

Expected:

Client:

```
{"type":"err","err":"sig_fail"}
```

Revert toggle after test.

---

# 🔁 Test 4 — REPLAY (Sequence Number Reuse)

Toggle in client.py:

```python
TEST_REPLAY = True
```
Effected
```python
if TEST_REPLAY:
    seq_to_send = 1   # force replay
else:
    seq_to_send = seq
```

Send message.

Client should get:

```
{"type":"err","err":"replay"}
```

Revert after test.

---

# 📜 Test 5 — Transcript + SessionReceipt Verification

After typing `/end`, client receives:

```json
{
  "type": "receipt",
  "first_seq": 1,
  "last_seq": 4,
  "transcript_sha256": "<hex>",
  "sig_b64": "<base64>"
}
```

Then run the offline verification:

### `tests/transcript_test.py`

```python
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from app.crypto.sign import public_from_cert_pem

TRANSCRIPT_SHA256 = "PUT_TRANSCRIPT_SHA256"
SIG_B64 = "PUT_SIG_B64"

pub = public_from_cert_pem(open("certs/server.cert.pem","rb").read())
tx_hash = bytes.fromhex(TRANSCRIPT_SHA256)
sig = base64.b64decode(SIG_B64)

try:
    pub.verify(sig, tx_hash, padding.PKCS1v15(), hashes.SHA256())
    print("VALID RECEIPT SIGNATURE ✔")
except Exception as e:
    print("INVALID SIGNATURE ❌", e)
```

Run:

```bash
python tests/transcript_test.py
```

You must show:

```
VALID RECEIPT SIGNATURE ✔
```

---

# 📁 Evidence Files

Place these under `tests/manual/evidence/`:

* `wiresharktest.png`
* `badcert.png`
* `sigfail.png`
* `replaytest.png`
* `transcrpt.png`
* `transcript_used.txt`
* `tcpdump.pcap`

---

# 🔧 Troubleshooting

### `bad server hello None`

Server crashed while starting → check server logs.

### `signature verification failed`

You probably signed hex instead of bytes → must sign `.digest()`.

### MySQL Connection Errors

Ensure Docker container is running and `.env` has correct credentials.

---

# ✔ Appendix — Helper Commands

```bash
python app/server.py
python app/client.py

sudo tcpdump -i lo -s 0 -w securechat.pcap port 9000

python tests/transcript_test.py

python -c "from app.storage import db; db.ensure_schema()"
```

---

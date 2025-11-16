from pydantic import BaseModel
from typing import Optional

class Hello(BaseModel):
    type: str = "hello"
    cert_pem: str
    nonce_b64: str

class ServerHello(BaseModel):
    type: str = "server_hello"
    cert_pem: str
    nonce_b64: str

class DHClient(BaseModel):
    type: str = "dh_client"
    g: str
    p: str
    A: str

class DHServer(BaseModel):
    type: str = "dh_server"
    B: str

class EncryptedPayload(BaseModel):
    type: str = "payload"
    payload_b64: str

class Message(BaseModel):
    type: str = "msg"
    seqno: int
    ts: int
    ct_b64: str
    sig_b64: str

class End(BaseModel):
    type: str = "end"

class Receipt(BaseModel):
    type: str = "receipt"
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig_b64: str

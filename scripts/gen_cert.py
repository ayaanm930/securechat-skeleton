import os, sys, datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

OUT = "certs"
os.makedirs(OUT, exist_ok=True)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/gen_cert.py <common_name>")
        sys.exit(1)
    cn = sys.argv[1]
    ca_key_path = os.path.join(OUT, "ca.key.pem")
    ca_cert_path = os.path.join(OUT, "ca.cert.pem")
    if not (os.path.exists(ca_key_path) and os.path.exists(ca_cert_path)):
        print("CA missing. Run scripts/gen_ca.py first.")
        sys.exit(1)
    with open(ca_key_path,"rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path,"rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=5))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
            .sign(ca_key, hashes.SHA256()))
    key_file = os.path.join(OUT, f"{cn}.key.pem")
    cert_file = os.path.join(OUT, f"{cn}.cert.pem")
    with open(key_file, "wb") as f:
        f.write(key_pem)
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Generated {key_file} and {cert_file}")

if __name__ == "__main__":
    main()

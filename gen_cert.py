"""
scripts/gen_cert.py
Issues a certificate signed by the Root CA.
"""
import argparse
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def load_ca(ca_dir="certs"):
    """Helper to load CA key and cert to sign with."""
    try:
        with open(os.path.join(ca_dir, "ca.crt"), "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(os.path.join(ca_dir, "ca.key"), "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        return ca_cert, ca_key
    except FileNotFoundError:
        print("[-] Error: Root CA not found. Run gen_ca.py first!")
        exit(1)

def generate_cert(cn, output_prefix, ca_dir="certs"):
    print(f"[*] Generating Certificate for CN={cn}...")
    
    # 1. Load the CA (The Issuer)
    ca_cert, ca_key = load_ca(ca_dir)
    
    # 2. Generate Private Key for the User (Client/Server)
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    
    # 3. Build the Certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat User"),
    ])
    
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(ca_cert.subject) # Signed by CA
    cert_builder = cert_builder.public_key(private_key.public_key())
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.not_valid_before(datetime.now(timezone.utc))
    cert_builder = cert_builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))

    # 4. Add Extensions
    # BasicConstraints: CA=False (This is a user, not a CA)
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    # SAN (Subject Alternative Name): Required for modern verification (e.g., matching hostnames)
    cert_builder = cert_builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False,
    )

    # 5. Sign with the CA's Private Key
    certificate = cert_builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend()
    )

    # 6. Save to Disk
    key_path = f"{output_prefix}.key"
    cert_path = f"{output_prefix}.crt"

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Issued: {cert_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Issue a certificate signed by Root CA")
    parser.add_argument("--cn", required=True, help="Common Name (e.g., server.local)")
    parser.add_argument("--out", required=True, help="Output path prefix (e.g., certs/server)")
    parser.add_argument("--ca-dir", default="certs", help="CA directory")
    args = parser.parse_args()
    
    generate_cert(args.cn, args.out, args.ca_dir)
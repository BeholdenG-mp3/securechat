"""
scripts/gen_ca.py
Generates a Root CA private key and self-signed certificate.
"""
import os
import argparse
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_ca(name="SecureChat Root CA", output_dir="certs"):
    print(f"[*] Generating Root CA: {name}")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # 1. Generate Private Key (RSA 2048)
    # Why: RSA 2048 is the standard for secure identity keys in this context.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. Build the Certificate
    # Self-signed means Subject == Issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES"),
    ])

    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(issuer)
    cert_builder = cert_builder.public_key(private_key.public_key())
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    
    # Validity: 10 years (Root CAs last a long time)
    cert_builder = cert_builder.not_valid_before(datetime.now(timezone.utc))
    cert_builder = cert_builder.not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=3650)
    )

    # 3. Add Extensions
    # CRITICAL: BasicConstraints ca=True tells verifiers "This cert can sign other certs"
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    
    # 4. Sign the certificate with its OWN private key (Self-Signed)
    certificate = cert_builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
    )

    # 5. Save to Disk (PEM format)
    key_path = os.path.join(output_dir, "ca.key")
    cert_path = os.path.join(output_dir, "ca.crt")
    
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Root CA generated: {cert_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument("--name", default="FAST-NU Root CA", help="Common Name for CA")
    parser.add_argument("--out", default="certs", help="Output directory")
    args = parser.parse_args()
    
    generate_ca(args.name, args.out)
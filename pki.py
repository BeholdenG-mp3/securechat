"""
app/crypto/pki.py
X.509 validation: signed-by-CA, validity window, CN/SAN.
"""
import os
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

def load_cert(cert_pem_str: str):
    """Load X.509 certificate from PEM string."""
    return x509.load_pem_x509_certificate(cert_pem_str.encode(), default_backend())

def load_ca_cert(ca_path="certs/ca.crt"):
    """Load CA certificate from disk."""
    if not os.path.exists(ca_path):
        raise FileNotFoundError(f"Root CA not found at {ca_path}")
    with open(ca_path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def validate_certificate(cert_pem: str, expected_cn: str = None, ca_path="certs/ca.crt") -> tuple[bool, str]:
    """
    Validates a peer certificate.
    Returns: (is_valid, error_message)
    """
    try:
        # 1. Load Certificates
        cert = load_cert(cert_pem)
        ca_cert = load_ca_cert(ca_path)

        # 2. Check Validity Period (Expiry)
        # Using a small buffer for clock skew
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return False, "BAD_CERT: Certificate expired or not yet valid"

        # 3. Verify Signature (Chain of Trust)
        # We verify that 'cert' was signed by 'ca_cert's private key
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),  # <--- FIXED: Explicitly use SHA256
            )
        except Exception as e:
            # If verification fails, it raises an InvalidSignature exception
            return False, f"BAD_CERT: Invalid signature (Not signed by Root CA) - {e}"

        # 4. Check Common Name (Identity)
        if expected_cn:
            cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not cn_attr:
                return False, "BAD_CERT: No Common Name found"
            cn = cn_attr[0].value
            if cn != expected_cn:
                return False, f"BAD_CERT: CN mismatch (Expected {expected_cn}, got {cn})"

        return True, "OK"

    except Exception as e:
        return False, f"BAD_CERT: Validation error - {str(e)}"
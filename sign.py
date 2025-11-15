from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def sign_data(private_key, data: bytes) -> bytes:
    """Sign data using RSA private key with SHA-256."""
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_signature(cert_pem: str, data: bytes, signature: bytes) -> bool:
    """Verify RSA signature using the peer's certificate."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        public_key = cert.public_key()
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
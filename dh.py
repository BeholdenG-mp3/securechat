import secrets
import hashlib

# Standard 2048-bit MODP Group (RFC 3526) - Safe for assignment use
# (Truncated for brevity, but real apps use the full hex string)
# For this assignment, we can use a standard integer or the full RFC value.
# Using a smaller safe prime for assignment performance if allowed, 
# but let's stick to a standard one.
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16
)
DH_G = 2

def generate_dh_keypair():
    """
    Returns (private_key, public_key)
    private_key: random integer [1, p-2]
    public_key: g^private_key mod p
    """
    private_key = secrets.randbelow(DH_P - 2) + 1
    public_key = pow(DH_G, private_key, DH_P)
    return private_key, public_key

def compute_dh_shared_secret(private_key, peer_public_key):
    """
    Returns shared_secret = peer_public_key^private_key mod p
    """
    return pow(peer_public_key, private_key, DH_P)

def derive_session_key(shared_secret: int) -> bytes:
    """
    Derives a 16-byte AES key from the DH shared secret.
    Formula: K = Trunc16(SHA256(big-endian bytes of K_s))
    """
    # 1. Convert int to bytes (big endian)
    # bit_length() + 7 // 8 ensures we get the minimum bytes needed
    byte_len = (shared_secret.bit_length() + 7) // 8
    secret_bytes = shared_secret.to_bytes(byte_len, byteorder='big')
    
    # 2. SHA-256 Hash
    digest = hashlib.sha256(secret_bytes).digest()
    
    # 3. Truncate to 16 bytes (128 bits)
    return digest[:16]
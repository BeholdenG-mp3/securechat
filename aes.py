import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def pad(data: bytes) -> bytes:
    """Apply PKCS#7 padding to data (block size 128 bits)."""
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad(padded_data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts data using AES-128 (ECB mode for this assignment scope).
    Note: ECB is generally not secure for large data, but standard for 
    basic block cipher assignments unless CBC/IV is specified.
    """
    # 1. Pad the plaintext
    padded_data = pad(plaintext)
    
    # 2. Encrypt
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypts AES-128 ECB ciphertext."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 3. Unpad
    return unpad(padded_data)
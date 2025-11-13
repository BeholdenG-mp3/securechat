"""
attacker.py
Simulates a MITM/Malicious client to test Integrity and Replay protections.
"""
import socket
import json
import os
import time
from app.common.protocol import *
from app.common.utils import *
from app.crypto.aes import aes_encrypt
from app.crypto.dh import generate_dh_keypair, compute_dh_shared_secret, derive_session_key
from app.crypto.sign import sign_data
from cryptography.hazmat.primitives import serialization

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999
CERT_PATH = "certs/client.crt"
KEY_PATH = "certs/client.key"

def load_creds():
    with open(CERT_PATH, 'r') as f:
        cert = f.read()
    with open(KEY_PATH, 'rb') as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    return cert, key

def run_attack_test():
    print("=== STARTING SECURITY TESTS ===")
    cert_pem, priv_key = load_creds()
    
    # Connect to Server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    
    # 1. Standard Handshake (We must be authenticated to attack)
    print("\n[*] Authenticating as legitimate user...")
    
    # Hello
    sock.send(HelloMsg(client_cert=cert_pem, nonce=b64e(os.urandom(16))).model_dump_json().encode())
    sock.recv(4096) # ServerHello
    
    # DH Auth
    priv, pub = generate_dh_keypair()
    sock.send(DHClientMsg(g=2, p=0, A=pub).model_dump_json().encode())
    data = sock.recv(4096).decode()
    dh_srv = DHServerMsg.model_validate_json(data)
    
    # Derive Temp Key
    shared = compute_dh_shared_secret(priv, dh_srv.B)
    temp_key = derive_session_key(shared)
    
    # Login (Use a user you already registered, e.g., 'alice')
    # NOTE: Ensure 'alice' exists in your DB!
    login_payload = LoginPayload(email="abc@gmail.com", pwd="12345678", nonce="123")
    ct = aes_encrypt(temp_key, login_payload.model_dump_json().encode())
    sock.send(AuthMsg(type="login", ct=b64e(ct)).model_dump_json().encode())
    res = sock.recv(4096).decode()
    
    if "success\":false" in res:
        print("[!] Login failed. Please register 'alice@example.com' with 'password123' first using the normal client.")
        return

    # Session DH
    priv_sess, pub_sess = generate_dh_keypair()
    sock.send(DHClientMsg(g=2, p=0, A=pub_sess).model_dump_json().encode())
    data = sock.recv(4096).decode()
    dh_srv = DHServerMsg.model_validate_json(data)
    shared_sess = compute_dh_shared_secret(priv_sess, dh_srv.B)
    session_key = derive_session_key(shared_sess)
    print("[+] Session Established. Launching Attacks...")

    # --- ATTACK 1: REPLAY ATTACK ---
    print("\n[Test 1] REPLAY ATTACK")
    
    # Construct a valid message
    msg_str = "This is a replay test"
    ts = now_ms()
    seq = 1
    ct_bytes = aes_encrypt(session_key, msg_str.encode())
    ct_str = b64e(ct_bytes)
    sig = b64e(sign_data(priv_key, f"{seq}{ts}{ct_str}".encode()))
    
    packet = ChatMsg(seqno=seq, ts=ts, ct=ct_str, sig=sig).model_dump_json().encode()
    
    print("   -> Sending Packet 1 (Valid)...")
    sock.send(packet)
    time.sleep(0.5)
    
    print("   -> Sending Packet 1 AGAIN (Replay)...")
    sock.send(packet) # SENDING EXACT SAME BYTES
    
    # --- ATTACK 2: TAMPER ATTACK ---
    print("\n[Test 2] TAMPER ATTACK (Integrity)")
    
    # Construct valid message
    msg_str = "Do not tamper with me"
    seq = 2
    ts = now_ms()
    ct_bytes = aes_encrypt(session_key, msg_str.encode())
    
    # TAMPER: Flip the last byte of the ciphertext
    tampered_bytes = bytearray(ct_bytes)
    tampered_bytes[-1] ^= 0xFF # XOR flip
    ct_str_bad = b64e(tampered_bytes)
    
    # Sign the ORIGINAL (so sig is valid for original, but mismatches tampered ct)
    # Or just sign the bad one? The server checks Sig(Payload). 
    # If we send (BadPayload, ValidSigForGoodPayload), verification fails.
    sig_valid = b64e(sign_data(priv_key, f"{seq}{ts}{b64e(ct_bytes)}".encode()))
    
    packet_bad = ChatMsg(seqno=seq, ts=ts, ct=ct_str_bad, sig=sig_valid).model_dump_json().encode()
    
    print("   -> Sending Tampered Packet (Bit flipped in CT)...")
    sock.send(packet_bad)
    
    print("\nCheck the Server Terminal. You should see 'Replay Detected' and 'Signature Failed'.")
    sock.close()

if __name__ == "__main__":
    run_attack_test()
"""
audit.py
Smart Offline Verification.
Automatically selects the correct certificate (Client vs Server) 
based on the message fingerprint.
"""
import sys
import os
import json
from app.storage.transcript import Transcript, get_cert_fingerprint
from app.crypto.sign import verify_signature
from app.common.utils import b64d

# CONFIGURATION
# Update this filename to match your new transcript!
TRANSCRIPT_FILE = "transcripts/client_127.0.0.1_9999.txt"
RECEIPT_FILE = TRANSCRIPT_FILE.replace('.txt', '_receipt.json')

SERVER_CERT = "certs/server.crt"
CLIENT_CERT = "certs/client.crt"

def load_cert_map():
    """Load both certs and map fingerprints to their PEM data."""
    mapping = {}
    
    # Load Server Cert
    if os.path.exists(SERVER_CERT):
        with open(SERVER_CERT, 'r') as f:
            pem = f.read()
            fp = get_cert_fingerprint(pem)
            mapping[fp] = ("Server", pem)
            
    # Load Client Cert
    if os.path.exists(CLIENT_CERT):
        with open(CLIENT_CERT, 'r') as f:
            pem = f.read()
            fp = get_cert_fingerprint(pem)
            mapping[fp] = ("Client", pem)
            
    return mapping

def audit_session():
    print(f"=== SMART AUDIT SESSION ===")
    
    if not os.path.exists(TRANSCRIPT_FILE):
        print(f"[!] Transcript not found: {TRANSCRIPT_FILE}")
        return

    cert_map = load_cert_map()
    print(f"[*] Loaded certificates for: {[name for name, _ in cert_map.values()]}")

    # 1. Verify Transcript Integrity
    print(f"\n[*] Step 1: Verifying Message Integrity...")
    with open(TRANSCRIPT_FILE, 'r') as f:
        lines = f.readlines()
    
    valid_msgs = 0
    for i, line in enumerate(lines):
        parts = line.strip().split('|')
        if len(parts) != 5: continue
        seq, ts, ct, sig, fp = parts
        
        # Identify Signer
        if fp not in cert_map:
            print(f"    [!] Msg {seq}: Unknown Signer (Fingerprint {fp} not found in certs)")
            return
        
        signer_name, cert_pem = cert_map[fp]
        
        # Verify
        payload = f"{seq}{ts}{ct}".encode()
        if verify_signature(cert_pem, payload, b64d(sig)):
            print(f"    [✓] Msg {seq}: Valid ({signer_name})")
            valid_msgs += 1
        else:
            print(f"    [X] Msg {seq}: INVALID SIGNATURE (Claimed signer: {signer_name})")
            return

    print(f"    [OK] All {valid_msgs} messages verified.")

    # 2. Verify Receipt
    print(f"\n[*] Step 2: Verifying Session Receipt...")
    if not os.path.exists(RECEIPT_FILE):
        print("[!] Receipt file not found.")
        return

    # Calculate actual hash
    t = Transcript(TRANSCRIPT_FILE)
    actual_hash = t.compute_hash()
    
    with open(RECEIPT_FILE, 'r') as f:
        receipt = json.load(f)
    
    if actual_hash == receipt['transcript_sha256']:
        print(f"    [✓] Transcript Hash Matches")
    else:
        print(f"    [X] Hash Mismatch! Transcript modified.")
        return

    # Verify Receipt Sig (Signed by the entity in 'peer' field)
    # Ideally, we check who generated the receipt. 
    # For this assignment, usually the Client generates it.
    # We will try verifying with the Client Cert first.
    
    receipt_sig = b64d(receipt['sig'])
    
    # Try verifying with Client Cert
    client_name, client_pem = cert_map.get(get_cert_fingerprint(open(CLIENT_CERT).read()), (None, None))
    
    if verify_signature(client_pem, actual_hash.encode(), receipt_sig):
        print(f"    [✓] Receipt Signature Valid (Signed by Client)")
        print(f"\n[SUCCESS] Non-Repudiation Proven.")
    else:
        print(f"    [X] Receipt Signature Invalid.")

if __name__ == "__main__":
    audit_session()
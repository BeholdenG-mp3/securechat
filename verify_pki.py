"""
verify_pki.py
Script to verify that your PKI implementation correctly accepts valid certs
and rejects invalid ones.
"""
from app.crypto.pki import validate_certificate

def test_pki():
    print("--- Starting PKI Verification ---\n")

    # 1. Read the valid Server Certificate we generated
    try:
        with open("certs/server.crt", "r") as f:
            cert_data = f.read()
    except FileNotFoundError:
        print("[-] Error: certs/server.crt not found. Did you run gen_cert.py?")
        return

    # TEST A: Valid Certificate
    # We expect this to return True because the CN matches "server.local"
    print("[*] Test A: Checking VALID certificate (server.local)...")
    is_valid, msg = validate_certificate(cert_data, expected_cn="server.local")
    
    if is_valid:
        print(f"   [PASS] {msg}")
    else:
        print(f"   [FAIL] Expected valid, got error: {msg}")

    print("\n" + "-"*30 + "\n")

    # TEST B: Invalid Hostname (Tamper Test)
    # We expect this to return False because "google.com" != "server.local"
    print("[*] Test B: Checking INVALID hostname (google.com)...")
    is_valid, msg = validate_certificate(cert_data, expected_cn="google.com")
    
    if not is_valid:
        print(f"   [PASS] System correctly rejected it: {msg}")
    else:
        print(f"   [FAIL] System accepted an invalid hostname! (This is a security hole)")

    print("\n--- Verification Complete ---")

if __name__ == "__main__":
    test_pki()
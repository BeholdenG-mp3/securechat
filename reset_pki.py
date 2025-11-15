"""
reset_pki.py
Resets PKI and generates BOTH Server and Client certificates.
"""
import os
import shutil
import subprocess
import sys

def main():
    print("=== SecureChat PKI Reset Tool ===")

    # 1. Clean Slate
    print("\n[*] Deleting old certificates...")
    if os.path.exists("certs"):
        shutil.rmtree("certs")
    os.makedirs("certs", exist_ok=True)

    # 2. Generate New Root CA
    print("[*] Generating New Root CA...")
    subprocess.run([sys.executable, "scripts/gen_ca.py", "--name", "FAST-NU Root CA"], check=True)

    # 3. Generate SERVER Certificate
    print("[*] Generating Server Certificate...")
    subprocess.run([sys.executable, "scripts/gen_cert.py", "--cn", "server.local", "--out", "certs/server"], check=True)

    # 4. Generate CLIENT Certificate (This was missing!)
    print("[*] Generating Client Certificate...")
    subprocess.run([sys.executable, "scripts/gen_cert.py", "--cn", "client.local", "--out", "certs/client"], check=True)

    # 5. Run Verification
    if os.path.exists("verify_pki.py"):
        print("\n[*] Running Verification Test...")
        subprocess.run([sys.executable, "verify_pki.py"])
    else:
        print("\n[!] verify_pki.py not found, skipping test.")

    print("\n[✓] Reset Complete. You have ca.crt, server.crt, and client.crt.")

if __name__ == "__main__":
    main()
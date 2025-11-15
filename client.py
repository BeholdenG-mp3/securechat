import socket
import threading
import os
import sys
from cryptography.hazmat.primitives import serialization
from app.common.protocol import *
from app.common.utils import *
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.dh import generate_dh_keypair, compute_dh_shared_secret, derive_session_key
from app.crypto.pki import validate_certificate
from app.crypto.sign import sign_data, verify_signature
from app.storage.transcript import Transcript, get_cert_fingerprint

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999
CERT_PATH = "certs/client.crt"
KEY_PATH = "certs/client.key"

class SecureChatClient:
    def __init__(self):
        self.sock = None
        self.session_key = None
        self.server_cert = None
        self.transcript = None
        self.my_seqno = 0
        self.server_seqno = 0
        self.load_credentials()

    def load_credentials(self):
        """Load Client's Certificate and Private Key"""
        if not os.path.exists(CERT_PATH) or not os.path.exists(KEY_PATH):
            print(f"[!] Critical: Client certs not found at {CERT_PATH}. Run reset_pki.py!")
            sys.exit(1)
            
        with open(CERT_PATH, 'r') as f:
            self.client_cert_pem = f.read()
        with open(KEY_PATH, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)

    def connect_and_handshake(self):
        """Phase 1: TCP Connection & Certificate Exchange"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_HOST, SERVER_PORT))
            print(f"[*] Connected to {SERVER_HOST}:{SERVER_PORT}")

            # 1. Send Hello
            hello = HelloMsg(client_cert=self.client_cert_pem, nonce=b64e(os.urandom(16)))
            self.sock.send(hello.model_dump_json().encode())

            # 2. Receive Server Hello
            data = self.sock.recv(4096).decode()
            srv_hello = ServerHelloMsg.model_validate_json(data)

            # 3. Validate Server Certificate
            # IMPORTANT: We expect the server's CN to be 'server.local'
            is_valid, err = validate_certificate(srv_hello.server_cert, expected_cn="server.local")
            if not is_valid:
                raise Exception(f"Server Certificate Invalid: {err}")
            
            self.server_cert = srv_hello.server_cert
            print("[✓] Server Authenticated via PKI.")
            return True
        except Exception as e:
            print(f"[!] Handshake Failed: {e}")
            return False

    def authenticate(self):
        """Phase 2 & 3: Key Agreement and Login/Register"""
        try:
            # 1. DH Exchange 1 (For Auth)
            priv_dh, pub_dh = generate_dh_keypair()
            self.sock.send(DHClientMsg(g=2, p=0, A=pub_dh).model_dump_json().encode())
            
            data = self.sock.recv(4096).decode()
            dh_server = DHServerMsg.model_validate_json(data)
            
            shared = compute_dh_shared_secret(priv_dh, dh_server.B)
            temp_key = derive_session_key(shared)
            
            # 2. User Input
            print("\n--- Authentication ---")
            print("1. Login")
            print("2. Register")
            choice = input("Select (1/2): ")
            
            auth_type = "login" if choice == "1" else "register"
            email = input("Email: ")
            
            payload_str = ""
            if auth_type == "register":
                user = input("Username: ")
                pwd = input("Password: ")
                # In this protocol, client sends the raw password (encrypted by temp_key)
                # The server handles the salting/hashing storage.
                reg_payload = RegisterPayload(email=email, username=user, pwd=pwd, salt="")
                payload_str = reg_payload.model_dump_json()
            else:
                pwd = input("Password: ")
                login_payload = LoginPayload(email=email, pwd=pwd, nonce=b64e(os.urandom(16)))
                payload_str = login_payload.model_dump_json()

            # 3. Encrypt Payload
            ct_bytes = aes_encrypt(temp_key, payload_str.encode())
            auth_msg = AuthMsg(type=auth_type, ct=b64e(ct_bytes))
            self.sock.send(auth_msg.model_dump_json().encode())

            # 4. Check Status
            data = self.sock.recv(4096).decode()
            status = StatusMsg.model_validate_json(data)
            
            if not status.success:
                print(f"[-] Authentication Failed: {status.message}")
                return False
            
            print(f"[+] {status.message}")
            return True

        except Exception as e:
            print(f"[!] Auth Error: {e}")
            return False

    def establish_session(self):
        """Phase 4: Session Key Agreement"""
        try:
            priv_sess, pub_sess = generate_dh_keypair()
            self.sock.send(DHClientMsg(g=2, p=0, A=pub_sess).model_dump_json().encode())
            
            data = self.sock.recv(4096).decode()
            dh_server = DHServerMsg.model_validate_json(data)
            
            shared = compute_dh_shared_secret(priv_sess, dh_server.B)
            self.session_key = derive_session_key(shared)
            print("[✓] Secure Session Established.")
            
            # Init Transcript
            t_path = f"transcripts/client_{SERVER_HOST}_{SERVER_PORT}.txt"
            self.transcript = Transcript(t_path)
            return True
        except Exception as e:
            print(f"[!] Session Setup Failed: {e}")
            return False

    def listen_loop(self):
        """Receive Messages Thread"""
        while True:
            try:
                data = self.sock.recv(8192).decode()
                if not data:
                    print("\n[!] Server disconnected.")
                    os._exit(0)
                
                chat_msg = ChatMsg.model_validate_json(data)
                
                # 1. Replay Check
                if chat_msg.seqno <= self.server_seqno:
                    # In a real app we might log this or warn
                    continue
                self.server_seqno = chat_msg.seqno
                
                # 2. Verify Signature
                payload = f"{chat_msg.seqno}{chat_msg.ts}{chat_msg.ct}".encode()
                if not verify_signature(self.server_cert, payload, b64d(chat_msg.sig)):
                    print("\n[!] Error: Invalid Message Signature!")
                    continue
                
                # 3. Decrypt
                pt = aes_decrypt(self.session_key, b64d(chat_msg.ct)).decode()
                
                # 4. Log
                fp = get_cert_fingerprint(self.server_cert)
                self.transcript.append(chat_msg.seqno, chat_msg.ts, chat_msg.ct, chat_msg.sig, fp)
                
                print(f"\n[Server]: {pt}")
                print("[You]: ", end='', flush=True)
                
            except Exception:
                # Connection likely closed
                break

    def chat_loop(self):
        """Phase 5: Main Chat Interface"""
        print("\n=== SECURE CHAT STARTED ===")
        print("Type 'quit' to exit and generate receipt.\n")
        
        # Start listener
        t = threading.Thread(target=self.listen_loop, daemon=True)
        t.start()
        
        while True:
            try:
                msg = input("[You]: ")
                if msg.lower() == 'quit':
                    self.generate_receipt()  # <--- ADD THIS CALL
                    break
                
                self.my_seqno += 1
                ts = now_ms()
                
                # Encrypt
                ct_bytes = aes_encrypt(self.session_key, msg.encode())
                ct_str = b64e(ct_bytes)
                
                # Sign (seqno + ts + ct)
                sig_payload = f"{self.my_seqno}{ts}{ct_str}".encode()
                sig_bytes = sign_data(self.private_key, sig_payload)
                
                # Send
                chat_msg = ChatMsg(
                    seqno=self.my_seqno,
                    ts=ts,
                    ct=ct_str,
                    sig=b64e(sig_bytes)
                )
                self.sock.send(chat_msg.model_dump_json().encode())
                
                # Log to transcript
                # Use YOUR OWN cert fingerprint because YOU signed this message
                # Fixed code:
                fp = get_cert_fingerprint(self.client_cert_pem)
                self.transcript.append(self.my_seqno, ts, ct_str, b64e(sig_bytes), fp)
                
            except KeyboardInterrupt:
                break
        
        # Generate Receipt on Exit
        print("\n[*] Generating Session Receipt...")
        h = self.transcript.compute_hash()
        print(f"[✓] Session Hash: {h}")
        # In a full implementation, you would write this to a receipt file
        self.sock.close()

    def generate_receipt(self):
        """Generates a signed receipt for the chat session."""
        print("\n[*] Generating Session Receipt...")
        
        # 1. Compute Transcript Hash
        t_hash = self.transcript.compute_hash()
        
        # 2. Get Sequence Range
        first, last = self.transcript.get_range()
        
        # 3. Sign the Hash (Proof of Non-Repudiation)
        # We sign the hash so we can't deny this specific transcript later
        sig_bytes = sign_data(self.private_key, t_hash.encode())
        
        # 4. Create the Receipt Object
        receipt = ReceiptMsg(
            peer="client",
            first_seq=first,
            last_seq=last,
            transcript_sha256=t_hash,
            sig=b64e(sig_bytes)
        )
        
        # 5. Save to Disk
        receipt_path = self.transcript.filepath.replace(".txt", "_receipt.json")
        with open(receipt_path, "w") as f:
            f.write(receipt.model_dump_json(indent=2))
            
        print(f"[✓] Receipt Saved: {receipt_path}")

if __name__ == "__main__":
    client = SecureChatClient()
    if client.connect_and_handshake():
        if client.authenticate():
            if client.establish_session():
                client.chat_loop()
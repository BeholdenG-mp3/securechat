import socket
import json
import os
import threading
from cryptography.hazmat.primitives import serialization
from app.common.protocol import *
from app.common.utils import *
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.dh import generate_dh_keypair, compute_dh_shared_secret, derive_session_key
from app.crypto.pki import validate_certificate
from app.crypto.sign import sign_data, verify_signature
from app.storage.db import create_user, verify_user
from app.storage.transcript import Transcript, get_cert_fingerprint

# Configuration
HOST = '0.0.0.0'
PORT = 9999
CERT_PATH = "certs/server.crt"
KEY_PATH = "certs/server.key"

class SecureChatServer:
    def __init__(self):
        self.load_credentials()
        
    def load_credentials(self):
        """Load Server's Certificate and Private Key"""
        try:
            with open(CERT_PATH, 'r') as f:
                self.server_cert_pem = f.read()
            with open(KEY_PATH, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            print(f"[+] Server credentials loaded from {CERT_PATH}")
        except FileNotFoundError:
            print(f"[!] Critical: Certs not found at {CERT_PATH}. Run reset_pki.py!")
            exit(1)

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[*] Server listening on {HOST}:{PORT}")
        
        try:
            while True:
                conn, addr = sock.accept()
                # Handle each client in a separate thread
                t = threading.Thread(target=self.handle_client, args=(conn, addr))
                t.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
        finally:
            sock.close()

    def handle_client(self, conn, addr):
        print(f"\n[+] Connection from {addr}")
        client_cert = None
        session_key = None
        transcript = None
        client_seqno = 0
        my_seqno = 0
        
        try:
            # --- PHASE 1: Certificate Exchange ---
            # 1. Receive Client Hello
            data = conn.recv(4096).decode()
            hello = HelloMsg.model_validate_json(data)
            
            # 2. Validate Client Cert
            is_valid, err = validate_certificate(hello.client_cert)
            if not is_valid:
                print(f"[!] Client Cert Invalid: {err}")
                conn.close()
                return
            client_cert = hello.client_cert
            print(f"[✓] Client Authenticated: {get_cert_fingerprint(client_cert)}")
            
            # 3. Send Server Hello
            srv_hello = ServerHelloMsg(server_cert=self.server_cert_pem, nonce=b64e(os.urandom(16)))
            conn.send(srv_hello.model_dump_json().encode())

            # --- PHASE 2: Auth Key Agreement ---
            # 4. Receive DH Params
            data = conn.recv(4096).decode()
            dh_client = DHClientMsg.model_validate_json(data)
            
            # 5. Compute Temp Key
            priv_dh, pub_dh = generate_dh_keypair()
            shared = compute_dh_shared_secret(priv_dh, dh_client.A)
            temp_key = derive_session_key(shared)
            
            # 6. Send DH Public Key
            conn.send(DHServerMsg(B=pub_dh).model_dump_json().encode())
            
            # --- PHASE 3: Registration / Login ---
            data = conn.recv(4096).decode()
            auth_msg = AuthMsg.model_validate_json(data)
            
            # Decrypt payload
            encrypted_bytes = b64d(auth_msg.ct)
            decrypted_bytes = aes_decrypt(temp_key, encrypted_bytes)
            
            success = False
            msg = "Auth Failed"
            
            if auth_msg.type == "register":
                reg_data = RegisterPayload.model_validate_json(decrypted_bytes.decode())
                # For this assignment, client sends hash. Server salts and stores.
                # Note: To match db.py, we create user with the raw 'pwd' field from client
                if create_user(reg_data.email, reg_data.username, reg_data.pwd):
                    success = True
                    msg = "Registration Successful"
                else:
                    msg = "User already exists"
                    
            elif auth_msg.type == "login":
                login_data = LoginPayload.model_validate_json(decrypted_bytes.decode())
                if verify_user(login_data.email, login_data.pwd):
                    success = True
                    msg = "Login Successful"
                else:
                    msg = "Invalid Credentials"

            conn.send(StatusMsg(success=success, message=msg).model_dump_json().encode())
            if not success:
                print(f"[-] Auth failed for {addr}")
                conn.close()
                return
            
            print(f"[+] Auth Success for {addr}")

            # --- PHASE 4: Session Key Agreement ---
            # Fresh DH for the actual chat
            data = conn.recv(4096).decode()
            dh_client_sess = DHClientMsg.model_validate_json(data)
            
            priv_sess, pub_sess = generate_dh_keypair()
            shared_sess = compute_dh_shared_secret(priv_sess, dh_client_sess.A)
            session_key = derive_session_key(shared_sess)
            
            conn.send(DHServerMsg(B=pub_sess).model_dump_json().encode())
            print(f"[+] Session Key Established.")
            
            # Init Transcript
            t_path = f"transcripts/server_{addr[0]}_{addr[1]}.txt"
            transcript = Transcript(t_path)

            # --- PHASE 5: Chat Loop ---
            while True:
                data = conn.recv(8192).decode()
                if not data: break
                
                # Check for receipt (Client requesting to close)
                if '"receipt"' in data: 
                    # Handle receipt logic if needed, or just break to close
                    break
                    
                # Handle Chat Msg
                chat_msg = ChatMsg.model_validate_json(data)
                
                # 1. Replay Check
                if chat_msg.seqno <= client_seqno:
                    print(f"[!] Replay Detected! Seq {chat_msg.seqno} <= {client_seqno}")
                    continue
                client_seqno = chat_msg.seqno
                
                # 2. Verify Sig
                sig_bytes = b64d(chat_msg.sig)
                ct_bytes = b64d(chat_msg.ct)
                # Sig covers: seqno + ts + ct_b64
                verify_payload = f"{chat_msg.seqno}{chat_msg.ts}{chat_msg.ct}".encode()
                
                if not verify_signature(client_cert, verify_payload, sig_bytes):
                    print(f"[!] Signature Failed!")
                    continue
                    
                # 3. Decrypt
                plaintext = aes_decrypt(session_key, ct_bytes).decode()
                
                # 4. Log
                transcript.append(chat_msg.seqno, chat_msg.ts, chat_msg.ct, chat_msg.sig, get_cert_fingerprint(client_cert))
                
                print(f"[Client]: {plaintext}")
                
                # Echo back (optional, or implementing chat console logic)
                # For this assignment, let's just print. 
                # Real bidirectional chat would require a sending thread.
                
        except Exception as e:
            print(f"[-] Error: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    server = SecureChatServer()
    server.start()
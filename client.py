"""
Secure Chat Client
- End-to-end encryption with AES-256-GCM
- RSA authentication
- Diffie-Hellman key exchange
- Nonce-based replay attack prevention
- Message integrity verification
- Client-side message decryption (server sees only ciphertext)
"""

import socket
import threading
import json
import time
import sys
from crypto_utils import CryptoUtils


class SecureChatClient:
    def __init__(self, username):
        self.username = username
        self.socket = None
        self.running = False
        
        # Generate client's RSA keypair for authentication
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
        
        # Server's public key (received during handshake)
        self.server_public_key = None
        
        # User management
        self.users = {}  # username -> public_key
        
        # End-to-end encryption: Session keys for each peer
        self.session_keys = {}  # username -> AES key (from DH exchange)
        
        # Diffie-Hellman parameters
        self.dh_p, self.dh_g = CryptoUtils.generate_dh_parameters()
        self.dh_private_keys = {}  # username -> DH private key
        
        # Received messages queue
        self.messages = []
        self.message_lock = threading.Lock()
    
    def connect(self, host='127.0.0.1', port=5555):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.running = True
            
            print(f"[CLIENT] Connected to server at {host}:{port}")
            
            # Receive server's public key
            server_msg = self._receive_message()
            if server_msg and server_msg.get('type') == 'server_public_key':
                self.server_public_key = server_msg.get('public_key')
                print("[CLIENT] Received server's public key")
            
            # Authenticate with server
            if not self._authenticate():
                print("[ERROR] Authentication failed")
                self.disconnect()
                return False
            
            print(f"[CLIENT] Successfully authenticated as '{self.username}'")
            
            # Start receiver thread
            receiver_thread = threading.Thread(target=self._receive_messages)
            receiver_thread.daemon = True
            receiver_thread.start()
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            return False
    
    def _authenticate(self):
        """Authenticate with the server using RSA signature"""
        # Generate nonce for replay attack prevention
        nonce = CryptoUtils.generate_timestamp_nonce()
        
        # Sign the authentication data
        auth_data = f"{self.username}:{nonce}"
        signature = CryptoUtils.sign_data(self.private_key, auth_data)
        
        # Send authentication request
        auth_msg = {
            'type': 'auth_request',
            'username': self.username,
            'public_key': self.public_key.decode(),
            'nonce': nonce,
            'signature': signature.hex()
        }
        
        self._send_message(auth_msg)
        
        # Wait for authentication response
        response = self._receive_message()
        
        if response and response.get('type') == 'auth_response':
            return response.get('success', False)
        
        return False
    
    def _receive_messages(self):
        """Background thread to receive messages"""
        while self.running:
            try:
                message = self._receive_message()
                
                if not message:
                    break
                
                msg_type = message.get('type')
                
                if msg_type == 'user_list':
                    self._handle_user_list(message)
                
                elif msg_type == 'chat_message':
                    self._handle_chat_message(message)
                
                elif msg_type == 'key_exchange':
                    self._handle_key_exchange(message)
                    
            except Exception as e:
                if self.running:
                    print(f"[ERROR] Receive error: {e}")
                break
        
        self.running = False
    
    def _handle_user_list(self, message):
        """Handle user list update"""
        users = message.get('users', [])
        
        self.users.clear()
        for user in users:
            username = user.get('username')
            public_key = user.get('public_key')
            if username != self.username:
                self.users[username] = public_key
        
        print(f"\n[USERS] Online users: {', '.join(self.users.keys()) if self.users else 'None'}")
        print("> ", end="", flush=True)
    
    def _handle_chat_message(self, message):
        """Handle incoming encrypted chat message (decrypt on client side)"""
        sender = message.get('from')
        encrypted_data = message.get('encrypted_data')
        
        if not sender or not encrypted_data:
            return
        
        # Check if we have a session key with this user
        if sender not in self.session_keys:
            print(f"\n[WARNING] No session key with {sender}. Initiating key exchange...")
            print("> ", end="", flush=True)
            return
        
        try:
            # Decrypt the message using session key (E2E decryption on client)
            session_key = self.session_keys[sender]
            
            plaintext = CryptoUtils.aes_decrypt(
                session_key,
                encrypted_data['nonce'],
                encrypted_data['ciphertext'],
                encrypted_data['tag']
            )
            
            # Display the decrypted message
            timestamp = message.get('timestamp', time.strftime('%H:%M:%S'))
            print(f"\n[{timestamp}] {sender}: {plaintext}")
            print("> ", end="", flush=True)
            
            with self.message_lock:
                self.messages.append({
                    'from': sender,
                    'message': plaintext,
                    'timestamp': timestamp
                })
        
        except Exception as e:
            print(f"\n[ERROR] Failed to decrypt message from {sender}: {e}")
            print("[INFO] The message may have been tampered with")
            print("> ", end="", flush=True)
    
    def _handle_key_exchange(self, message):
        """Handle Diffie-Hellman key exchange"""
        sender = message.get('from')
        other_dh_public = message.get('dh_public')
        p = message.get('p')
        g = message.get('g')
        nonce = message.get('nonce')
        signature_hex = message.get('signature')
        
        if not all([sender, other_dh_public, p, g, nonce, signature_hex]):
            return
        
        # Verify the signature to prevent MITM attacks
        sender_public_key = self.users.get(sender)
        if not sender_public_key:
            print(f"\n[WARNING] Unknown user {sender}")
            print("> ", end="", flush=True)
            return
        
        signature_data = f"{sender}:{self.username}:{other_dh_public}:{nonce}"
        signature = bytes.fromhex(signature_hex)
        
        if not CryptoUtils.verify_signature(sender_public_key.encode(), signature_data, signature):
            print(f"\n[SECURITY] Invalid signature in key exchange from {sender} - possible MITM attack!")
            print("> ", end="", flush=True)
            return
        
        print(f"\n[KEY EXCHANGE] Received DH public key from {sender}")
        
        # Check if we initiated the exchange
        if sender in self.dh_private_keys:
            # We initiated, compute shared secret
            dh_private = self.dh_private_keys[sender]
            shared_secret = CryptoUtils.compute_dh_shared_secret(dh_private, other_dh_public, p)
            self.session_keys[sender] = shared_secret
            
            print(f"[KEY EXCHANGE] Established secure session with {sender}")
            print("> ", end="", flush=True)
        else:
            # They initiated, respond with our DH public key
            dh_private = CryptoUtils.generate_dh_private_key()
            dh_public = CryptoUtils.compute_dh_public_key(dh_private, p, g)
            
            # Compute shared secret
            shared_secret = CryptoUtils.compute_dh_shared_secret(dh_private, other_dh_public, p)
            self.session_keys[sender] = shared_secret
            
            # Send our DH public key back (signed to prevent MITM)
            response_nonce = CryptoUtils.generate_timestamp_nonce()
            signature_data = f"{self.username}:{sender}:{dh_public}:{response_nonce}"
            signature = CryptoUtils.sign_data(self.private_key, signature_data)
            
            key_exchange_msg = {
                'type': 'key_exchange',
                'to': sender,
                'dh_public': dh_public,
                'p': p,
                'g': g,
                'nonce': response_nonce,
                'signature': signature.hex()
            }
            
            self._send_message(key_exchange_msg)
            
            print(f"[KEY EXCHANGE] Established secure session with {sender}")
            print("> ", end="", flush=True)
    
    def initiate_key_exchange(self, username):
        """Initiate Diffie-Hellman key exchange with a user"""
        if username not in self.users:
            print(f"[ERROR] User '{username}' not found")
            return False
        
        if username in self.session_keys:
            print(f"[INFO] Session key already exists with {username}")
            return True
        
        # Generate DH private key
        dh_private = CryptoUtils.generate_dh_private_key()
        dh_public = CryptoUtils.compute_dh_public_key(dh_private, self.dh_p, self.dh_g)
        
        # Store private key for this exchange
        self.dh_private_keys[username] = dh_private
        
        # Sign the exchange to prevent MITM
        nonce = CryptoUtils.generate_timestamp_nonce()
        signature_data = f"{self.username}:{username}:{dh_public}:{nonce}"
        signature = CryptoUtils.sign_data(self.private_key, signature_data)
        
        # Send key exchange message
        key_exchange_msg = {
            'type': 'key_exchange',
            'to': username,
            'dh_public': dh_public,
            'p': self.dh_p,
            'g': self.dh_g,
            'nonce': nonce,
            'signature': signature.hex()
        }
        
        self._send_message(key_exchange_msg)
        print(f"[KEY EXCHANGE] Initiated with {username}")
        
        return True
    
    def send_message(self, recipient, plaintext):
        """Send encrypted message to recipient (end-to-end encryption)"""
        if recipient not in self.users:
            print(f"[ERROR] User '{recipient}' not found")
            return False
        
        # Check if we have a session key
        if recipient not in self.session_keys:
            print(f"[INFO] No session key with {recipient}. Initiating key exchange...")
            self.initiate_key_exchange(recipient)
            print("[INFO] Please wait for key exchange to complete before sending messages")
            return False
        
        try:
            # Encrypt message with session key (E2E encryption)
            session_key = self.session_keys[recipient]
            encrypted_data = CryptoUtils.aes_encrypt(session_key, plaintext)
            
            # Generate nonce for replay attack prevention
            nonce = CryptoUtils.generate_timestamp_nonce()
            
            # Send encrypted message
            message = {
                'type': 'chat_message',
                'to': recipient,
                'nonce': nonce,
                'encrypted_data': encrypted_data,
                'timestamp': time.strftime('%H:%M:%S')
            }
            
            self._send_message(message)
            
            # Display sent message locally
            timestamp = time.strftime('%H:%M:%S')
            print(f"[{timestamp}] You -> {recipient}: {plaintext}")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to send message: {e}")
            return False
    
    def _send_message(self, message):
        """Send JSON message to server"""
        try:
            json_data = json.dumps(message)
            message_bytes = json_data.encode('utf-8')
            
            # Send message length first (4 bytes)
            length = len(message_bytes)
            self.socket.sendall(length.to_bytes(4, 'big'))
            
            # Send the actual message
            self.socket.sendall(message_bytes)
        except Exception as e:
            if self.running:
                raise e
    
    def _receive_message(self):
        """Receive JSON message from server"""
        try:
            # Receive message length (4 bytes)
            length_bytes = self._receive_exact(4)
            if not length_bytes:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Receive the actual message
            message_bytes = self._receive_exact(length)
            if not message_bytes:
                return None
            
            json_data = message_bytes.decode('utf-8')
            return json.loads(json_data)
        except:
            return None
    
    def _receive_exact(self, num_bytes):
        """Receive exact number of bytes"""
        data = b''
        while len(data) < num_bytes:
            chunk = self.socket.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def list_users(self):
        """List online users"""
        if not self.users:
            print("No other users online")
        else:
            print("Online users:")
            for username in self.users.keys():
                session_status = "🔒 Secure" if username in self.session_keys else "🔓 No session"
                print(f"  - {username} ({session_status})")
    
    def disconnect(self):
        """Disconnect from server"""
        self.running = False
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        print("[CLIENT] Disconnected")
    
    def interactive_mode(self):
        """Interactive chat mode"""
        print("\n=== Secure Chat Client ===")
        print("Commands:")
        print("  /list - List online users")
        print("  /key <username> - Initiate key exchange")
        print("  /msg <username> <message> - Send message")
        print("  /quit - Quit")
        print("Or use: @username message")
        print("=" * 30)
        
        while self.running:
            try:
                user_input = input("> ").strip()
                
                if not user_input:
                    continue
                
                if user_input == '/quit':
                    break
                
                elif user_input == '/list':
                    self.list_users()
                
                elif user_input.startswith('/key '):
                    parts = user_input.split(' ', 1)
                    if len(parts) >= 2:
                        self.initiate_key_exchange(parts[1])
                    else:
                        print("Usage: /key <username>")
                
                elif user_input.startswith('/msg '):
                    parts = user_input.split(' ', 2)
                    if len(parts) >= 3:
                        recipient = parts[1]
                        message = parts[2]
                        self.send_message(recipient, message)
                    else:
                        print("Usage: /msg <username> <message>")
                
                elif user_input.startswith('@'):
                    parts = user_input[1:].split(' ', 1)
                    if len(parts) >= 2:
                        recipient = parts[0]
                        message = parts[1]
                        self.send_message(recipient, message)
                    else:
                        print("Usage: @username message")
                
                else:
                    print("Unknown command. Type /quit to exit, /list to see users")
            
            except KeyboardInterrupt:
                print()
                break
            except Exception as e:
                print(f"[ERROR] {e}")
        
        self.disconnect()


def main():
    if len(sys.argv) < 2:
        print("Usage: python client.py <username> [host] [port]")
        sys.exit(1)
    
    username = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5555
    
    client = SecureChatClient(username)
    
    if client.connect(host, port):
        # Give time for user list to arrive
        time.sleep(0.5)
        client.interactive_mode()


if __name__ == "__main__":
    main()

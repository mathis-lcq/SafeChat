"""
Secure Chat Server
- Handles client connections
- Performs RSA authentication
- Routes encrypted messages (sees only ciphertext)
- Implements DoS protection with rate limiting
- Prevents replay attacks with nonce tracking
"""

import socket
import threading
import json
import time
from collections import defaultdict
from crypto_utils import CryptoUtils


class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        
        # Generate server's RSA keypair for authentication
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
        
        # Client management
        self.clients = {}  # username -> {socket, public_key, last_seen}
        self.client_lock = threading.Lock()
        
        # Security: Nonce tracking for replay attack prevention
        self.used_nonces = set()
        self.nonce_lock = threading.Lock()
        self.nonce_cleanup_interval = 300  # Clean old nonces every 5 minutes
        
        # DoS Protection: Rate limiting
        self.rate_limit_tracker = defaultdict(list)  # IP -> [timestamps]
        self.max_requests_per_minute = 60
        self.connection_attempts = defaultdict(int)  # IP -> count
        self.max_connection_attempts = 5
        
        # Start nonce cleanup thread
        self.running = True
        threading.Thread(target=self._cleanup_nonces, daemon=True).start()
    
    def _cleanup_nonces(self):
        """Periodically clean up old nonces to prevent memory bloat"""
        while self.running:
            time.sleep(self.nonce_cleanup_interval)
            with self.nonce_lock:
                # Keep only recent nonces (last 5 minutes)
                current_time = int(time.time() * 1000)
                valid_nonces = set()
                for nonce in self.used_nonces:
                    try:
                        timestamp_str = nonce.split(':')[0]
                        timestamp = int(timestamp_str)
                        if current_time - timestamp < 300000:  # 5 minutes
                            valid_nonces.add(nonce)
                    except:
                        pass
                self.used_nonces = valid_nonces
    
    def _check_rate_limit(self, client_ip):
        """DoS Protection: Check if client exceeds rate limit"""
        current_time = time.time()
        
        # Clean old timestamps
        self.rate_limit_tracker[client_ip] = [
            ts for ts in self.rate_limit_tracker[client_ip]
            if current_time - ts < 60
        ]
        
        # Check if limit exceeded
        if len(self.rate_limit_tracker[client_ip]) >= self.max_requests_per_minute:
            return False
        
        # Add current timestamp
        self.rate_limit_tracker[client_ip].append(current_time)
        return True
    
    def _check_connection_attempt(self, client_ip):
        """DoS Protection: Limit connection attempts"""
        self.connection_attempts[client_ip] += 1
        
        if self.connection_attempts[client_ip] > self.max_connection_attempts:
            # Reset after 5 minutes
            return False
        
        return True
    
    def _verify_nonce(self, nonce):
        """Replay Attack Prevention: Verify nonce hasn't been used"""
        with self.nonce_lock:
            if nonce in self.used_nonces:
                return False
            
            # Verify timestamp is recent (within 60 seconds)
            if not CryptoUtils.verify_timestamp_nonce(nonce, max_age_seconds=60):
                return False
            
            self.used_nonces.add(nonce)
            return True
    
    def start(self):
        """Start the server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        print(f"[SERVER] Secure Chat Server started on {self.host}:{self.port}")
        print(f"[SERVER] Server public key:\n{self.public_key.decode()}")
        
        try:
            while self.running:
                client_socket, address = self.server_socket.accept()
                client_ip = address[0]
                
                # DoS Protection: Check connection attempts
                if not self._check_connection_attempt(client_ip):
                    print(f"[SECURITY] Too many connection attempts from {client_ip}")
                    client_socket.close()
                    continue
                
                print(f"[SERVER] Connection from {address}")
                
                # Handle client in a separate thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
        finally:
            self.stop()
    
    def _handle_client(self, client_socket, address):
        """Handle individual client connection"""
        client_ip = address[0]
        username = None
        
        try:
            # Authentication Phase
            # 1. Send server's public key
            self._send_message(client_socket, {
                'type': 'server_public_key',
                'public_key': self.public_key.decode()
            })
            
            # 2. Receive client's authentication request
            auth_msg = self._receive_message(client_socket)
            
            if not auth_msg or auth_msg.get('type') != 'auth_request':
                print(f"[SECURITY] Invalid authentication from {address}")
                client_socket.close()
                return
            
            # 3. Verify nonce to prevent replay attacks
            nonce = auth_msg.get('nonce')
            if not nonce or not self._verify_nonce(nonce):
                print(f"[SECURITY] Invalid or replayed nonce from {address}")
                self._send_message(client_socket, {
                    'type': 'auth_response',
                    'success': False,
                    'error': 'Invalid or replayed nonce'
                })
                client_socket.close()
                return
            
            # 4. Verify signature (RSA authentication)
            username = auth_msg.get('username')
            client_public_key = auth_msg.get('public_key')
            signature_hex = auth_msg.get('signature')
            
            if not all([username, client_public_key, signature_hex]):
                print(f"[SECURITY] Incomplete authentication from {address}")
                client_socket.close()
                return
            
            # Verify the signature
            signature = bytes.fromhex(signature_hex)
            auth_data = f"{username}:{nonce}"
            
            if not CryptoUtils.verify_signature(client_public_key.encode(), auth_data, signature):
                print(f"[SECURITY] Invalid signature from {address}")
                self._send_message(client_socket, {
                    'type': 'auth_response',
                    'success': False,
                    'error': 'Authentication failed'
                })
                client_socket.close()
                return
            
            # 5. Authentication successful
            with self.client_lock:
                self.clients[username] = {
                    'socket': client_socket,
                    'public_key': client_public_key,
                    'address': address,
                    'last_seen': time.time()
                }
            
            print(f"[SERVER] User '{username}' authenticated from {address}")
            
            self._send_message(client_socket, {
                'type': 'auth_response',
                'success': True
            })
            
            # Broadcast user list update
            self._broadcast_user_list()
            
            # Message handling loop
            while self.running:
                # DoS Protection: Rate limiting
                if not self._check_rate_limit(client_ip):
                    print(f"[SECURITY] Rate limit exceeded for {username} ({client_ip})")
                    time.sleep(1)  # Slow down the client
                    continue
                
                message = self._receive_message(client_socket)
                
                if not message:
                    break
                
                # Update last seen
                with self.client_lock:
                    if username in self.clients:
                        self.clients[username]['last_seen'] = time.time()
                
                # Handle different message types
                msg_type = message.get('type')
                
                if msg_type == 'chat_message':
                    # Verify nonce to prevent replay attacks
                    msg_nonce = message.get('nonce')
                    if not msg_nonce or not self._verify_nonce(msg_nonce):
                        print(f"[SECURITY] Replay attack detected from {username}")
                        continue
                    
                    # Route encrypted message (server can't read it)
                    self._route_message(username, message)
                
                elif msg_type == 'get_users':
                    self._send_user_list(client_socket)
                
                elif msg_type == 'key_exchange':
                    # Route DH key exchange messages
                    self._route_key_exchange(username, message)
        
        except Exception as e:
            print(f"[ERROR] Error handling client {username or address}: {e}")
        
        finally:
            # Clean up
            if username:
                with self.client_lock:
                    if username in self.clients:
                        del self.clients[username]
                print(f"[SERVER] User '{username}' disconnected")
                self._broadcast_user_list()
            
            try:
                client_socket.close()
            except:
                pass
    
    def _route_message(self, sender, message):
        """Route encrypted message to recipient (server can't decrypt)"""
        recipient = message.get('to')
        
        if not recipient:
            return
        
        with self.client_lock:
            if recipient in self.clients:
                recipient_socket = self.clients[recipient]['socket']
                
                # Forward the encrypted message (including all encrypted data)
                forward_msg = {
                    'type': 'chat_message',
                    'from': sender,
                    'nonce': message.get('nonce'),
                    'encrypted_data': message.get('encrypted_data'),
                    'timestamp': message.get('timestamp')
                }
                
                self._send_message(recipient_socket, forward_msg)
                print(f"[SERVER] Routed encrypted message from {sender} to {recipient} (ciphertext only)")
    
    def _route_key_exchange(self, sender, message):
        """Route Diffie-Hellman key exchange messages"""
        recipient = message.get('to')
        
        if not recipient:
            return
        
        with self.client_lock:
            if recipient in self.clients:
                recipient_socket = self.clients[recipient]['socket']
                
                forward_msg = {
                    'type': 'key_exchange',
                    'from': sender,
                    'dh_public': message.get('dh_public'),
                    'p': message.get('p'),
                    'g': message.get('g'),
                    'nonce': message.get('nonce'),
                    'signature': message.get('signature')
                }
                
                self._send_message(recipient_socket, forward_msg)
                print(f"[SERVER] Routed key exchange from {sender} to {recipient}")
    
    def _broadcast_user_list(self):
        """Broadcast updated user list to all clients"""
        with self.client_lock:
            user_list = []
            for username, client_info in self.clients.items():
                user_list.append({
                    'username': username,
                    'public_key': client_info['public_key']
                })
            
            message = {
                'type': 'user_list',
                'users': user_list
            }
            
            for client_info in self.clients.values():
                try:
                    self._send_message(client_info['socket'], message)
                except:
                    pass
    
    def _send_user_list(self, client_socket):
        """Send user list to a specific client"""
        with self.client_lock:
            user_list = []
            for username, client_info in self.clients.items():
                user_list.append({
                    'username': username,
                    'public_key': client_info['public_key']
                })
            
            message = {
                'type': 'user_list',
                'users': user_list
            }
            
            self._send_message(client_socket, message)
    
    def _send_message(self, client_socket, message):
        """Send JSON message to client"""
        try:
            json_data = json.dumps(message)
            message_bytes = json_data.encode('utf-8')
            
            # Send message length first (4 bytes)
            length = len(message_bytes)
            client_socket.sendall(length.to_bytes(4, 'big'))
            
            # Send the actual message
            client_socket.sendall(message_bytes)
        except Exception as e:
            raise e
    
    def _receive_message(self, client_socket):
        """Receive JSON message from client"""
        try:
            # Receive message length (4 bytes)
            length_bytes = self._receive_exact(client_socket, 4)
            if not length_bytes:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Receive the actual message
            message_bytes = self._receive_exact(client_socket, length)
            if not message_bytes:
                return None
            
            json_data = message_bytes.decode('utf-8')
            return json.loads(json_data)
        except:
            return None
    
    def _receive_exact(self, client_socket, num_bytes):
        """Receive exact number of bytes"""
        data = b''
        while len(data) < num_bytes:
            chunk = client_socket.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def stop(self):
        """Stop the server"""
        self.running = False
        
        with self.client_lock:
            for client_info in self.clients.values():
                try:
                    client_info['socket'].close()
                except:
                    pass
            self.clients.clear()
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("[SERVER] Server stopped")


if __name__ == "__main__":
    server = SecureChatServer(host='0.0.0.0', port=5555)
    server.start()

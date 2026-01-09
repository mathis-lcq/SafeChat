# Secure End-to-End Encrypted Chat Application

A secure chat application implementing end-to-end encryption and comprehensive security measures including RSA authentication, AES-256-GCM encryption, Diffie-Hellman key exchange, and protection against MITM, replay, DoS, and tampering attacks.

## 🔐 Security Features

### Encryption & Authentication
- **RSA-2048 Authentication**: Each client authenticates with the server using RSA digital signatures
- **AES-256-GCM End-to-End Encryption**: Messages are encrypted on the sender's client and decrypted only on the recipient's client
- **Diffie-Hellman Key Exchange**: Secure session key establishment between peers
- **Digital Signatures**: All key exchanges are signed to prevent tampering

### Attack Prevention

#### 1. **Man-in-the-Middle (MITM) Protection**
- RSA signatures verify identity during authentication
- DH public keys are signed during key exchange

#### 2. **Replay Attack Prevention**
- Timestamp-based nonces on all authentication requests and messages
- Server tracks used nonces and rejects duplicates

#### 3. **Denial of Service (DoS) Protection**
- Rate limiting: Max 60 requests per minute per client
- Connection attempt limiting: Max 5 attempts per IP
- Old nonce cleanup prevents memory bloat

#### 4. **Tampering Protection**
- AES-GCM provides authenticated encryption (integrity + confidentiality)
- Any modification to ciphertext is detected during decryption

### Privacy Guarantees
- **Server Cannot Read Messages**: Server only sees ciphertext
- **Client-Side Decryption**: Messages are decrypted only on recipient's machine
- **Perfect Forward Secrecy**: Each peer-to-peer session has unique keys

## 📋 Requirements

```bash
pip install -r requirements.txt
```

**Dependencies:**
- `pycryptodome==3.19.0` - Cryptographic primitives

## 🚀 Quick Start

### 1. Start the Server

```bash
python server.py
```

The server will start on `0.0.0.0:5555` and display its public key.

### 2. Start Clients

Open multiple terminals and start clients with different usernames:

```bash
# Terminal 1
python client.py alice

# Terminal 2
python client.py bob

# Terminal 3
python client.py charlie
```

To connect to a remote server:
```bash
python client.py alice 192.168.1.100 5555
```

### 3. Using the Chat

#### List Online Users
```
> /list
```

#### Initiate Secure Session (Key Exchange)
Before sending messages, establish a secure session:
```
> /key bob
```

#### Send Encrypted Messages
```
> @bob Hello, this is encrypted!
```

Or use the `/msg` command:
```
> /msg bob This message is end-to-end encrypted
```

#### Available Commands
- `/list` - Show online users and session status
- `/key <username>` - Initiate Diffie-Hellman key exchange
- `/msg <username> <message>` - Send encrypted message
- `@username <message>` - Shortcut to send message
- `/quit` - Exit the application

## 🔧 Architecture

### Communication Flow

```
1. Client connects to server
2. Server sends its RSA public key
3. Client authenticates with signed nonce
4. Server verifies signature and nonce freshness
5. Client receives list of online users

6. Client A initiates key exchange with Client B
   - Generates DH private key
   - Computes DH public key
   - Signs (username:recipient:DH_public:nonce)
   - Sends to server

7. Server routes DH message to Client B (cannot read it)

8. Client B receives DH message
   - Verifies signature (prevents MITM)
   - Generates own DH key pair
   - Computes shared secret
   - Responds with signed DH public key

9. Client A receives response
   - Verifies signature
   - Computes shared secret
   - Now both have same AES-256 session key

10. Encrypted messaging
    - Sender encrypts with AES-GCM using session key
    - Sends ciphertext + nonce + tag to server
    - Server routes ciphertext (cannot decrypt)
    - Recipient decrypts and verifies integrity
```

### Cryptographic Protocols

#### RSA Authentication (2048-bit)
```
Client → Server: {username, RSA_public_key, sign(username:nonce), nonce}
Server: Verify signature using client's public key
Server: Check nonce freshness and uniqueness
Server → Client: {authentication_success}
```

#### Diffie-Hellman Key Exchange (2048-bit safe prime)
```
p = 2048-bit safe prime (RFC 3526 Group 14)
g = 2 (generator)

Client A:
  private_A = random(256 bits)
  public_A = g^private_A mod p
  signature_A = sign(A:B:public_A:nonce)
  
Client B:
  private_B = random(256 bits)
  public_B = g^private_B mod p
  signature_B = sign(B:A:public_B:nonce)

Shared Secret:
  Client A: shared = public_B^private_A mod p
  Client B: shared = public_A^private_B mod p
  Session Key = SHA256(shared) [256 bits for AES-256]
```

#### AES-256-GCM Encryption
```
Encryption:
  nonce = random(96 bits)
  ciphertext, tag = AES-GCM-Encrypt(key, plaintext, nonce)
  
Decryption:
  plaintext = AES-GCM-Decrypt(key, ciphertext, nonce, tag)
  # Fails if ciphertext or tag was modified (tampering detection)
```

## 🛡️ Security Analysis

### Threat Model

| Attack Type | Protection Mechanism | Implementation |
|-------------|---------------------|----------------|
| **MITM** | RSA signatures on all exchanges | `CryptoUtils.verify_signature()` |
| **Replay** | Timestamp nonces + tracking | `_verify_nonce()`, `used_nonces` set |
| **DoS** | Rate limiting + connection limits | `_check_rate_limit()`, `max_requests_per_minute` |
| **Tampering** | AES-GCM authenticated encryption | `AES.MODE_GCM` with tag verification |
| **Eavesdropping** | E2E encryption, server sees only ciphertext | Client-side `aes_decrypt()` |
| **Key Compromise** | Perfect forward secrecy via DH | Unique session keys per peer pair |
| **Impersonation** | RSA authentication | `sign_data()` + `verify_signature()` |

### Security Properties

✅ **Confidentiality**: AES-256-GCM encryption  
✅ **Integrity**: GCM authentication tags  
✅ **Authentication**: RSA digital signatures  
✅ **Non-repudiation**: Signed key exchanges  
✅ **Forward Secrecy**: DH ephemeral keys  
✅ **Replay Protection**: Timestamp nonces  
✅ **MITM Protection**: Signed DH exchanges  
✅ **DoS Resilience**: Rate limiting  

## 📁 Project Structure

```
TEST2/
├── crypto_utils.py      # Cryptographic primitives and utilities
├── server.py            # Secure chat server (routes ciphertext only)
├── client.py            # Chat client with E2E encryption
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## 🔍 Code Components

### crypto_utils.py
- `generate_rsa_keypair()` - RSA-2048 key generation
- `rsa_encrypt/decrypt()` - RSA encryption operations
- `sign_data/verify_signature()` - Digital signatures
- `generate_dh_parameters()` - DH group parameters (RFC 3526)
- `compute_dh_shared_secret()` - DH key agreement
- `aes_encrypt/decrypt()` - AES-256-GCM operations
- `generate_timestamp_nonce()` - Replay-resistant nonces
- `verify_timestamp_nonce()` - Nonce freshness validation

### server.py
- RSA authentication handler
- Nonce tracking and cleanup
- Rate limiting for DoS protection
- Message routing (ciphertext only)
- User management and broadcasting

### client.py
- End-to-end message encryption/decryption
- Diffie-Hellman key exchange initiation
- Signature verification for MITM protection
- Interactive chat interface

## 🧪 Testing Security Features

### Test Replay Attack Prevention
1. Start server and two clients
2. Capture a network packet (message or auth)
3. Replay the same packet
4. Server will reject with "Invalid or replayed nonce"

### Test MITM Protection
1. Modify a DH public key during key exchange
2. Signature verification will fail
3. Client displays "Invalid signature - possible MITM attack!"

### Test Tampering Detection
1. Intercept encrypted message
2. Modify ciphertext or tag bytes
3. Decryption will fail with integrity error
4. Client displays "The message may have been tampered with"

### Test DoS Protection
1. Send more than 60 requests in one minute
2. Server rate limits and slows down responses
3. Try more than 5 connection attempts rapidly
4. Server blocks the IP temporarily

### Test E2E Encryption
1. Enable server debug logging
2. Send messages between clients
3. Server logs show only ciphertext, never plaintext
4. Only recipient client can decrypt



"""
Cryptographic utilities for secure chat application
Implements RSA, AES-GCM, Diffie-Hellman, and nonce generation
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import json
import time


class CryptoUtils:
    """Handles all cryptographic operations"""
    
    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        """Generate RSA key pair for authentication"""
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    
    @staticmethod
    def rsa_encrypt(public_key_pem, data):
        """Encrypt data with RSA public key"""
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data)
    
    @staticmethod
    def rsa_decrypt(private_key_pem, encrypted_data):
        """Decrypt data with RSA private key"""
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(encrypted_data)
    
    @staticmethod
    def generate_dh_parameters():
        """
        Generate Diffie-Hellman parameters
        Using a safe prime for the group
        """
        # Using a 2048-bit safe prime (RFC 3526 Group 14)
        p = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
        )
        g = 2
        return p, g
    
    @staticmethod
    def generate_dh_private_key():
        """Generate random private key for DH"""
        return int.from_bytes(get_random_bytes(32), 'big')
    
    @staticmethod
    def compute_dh_public_key(private_key, p, g):
        """Compute DH public key: g^private mod p"""
        return pow(g, private_key, p)
    
    @staticmethod
    def compute_dh_shared_secret(private_key, other_public_key, p):
        """Compute shared secret: other_public^private mod p"""
        shared_secret = pow(other_public_key, private_key, p)
        # Derive a 256-bit key from the shared secret using SHA256
        hash_obj = SHA256.new()
        hash_obj.update(shared_secret.to_bytes(256, 'big'))
        return hash_obj.digest()
    
    @staticmethod
    def aes_encrypt(key, plaintext, nonce=None):
        """
        Encrypt with AES-256-GCM (authenticated encryption)
        Provides confidentiality and integrity
        """
        if nonce is None:
            nonce = get_random_bytes(12)  # 96-bit nonce for GCM
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        
        return {
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex(),
            'tag': tag.hex()
        }
    
    @staticmethod
    def aes_decrypt(key, nonce_hex, ciphertext_hex, tag_hex):
        """Decrypt AES-GCM encrypted data"""
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        tag = bytes.fromhex(tag_hex)
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.decode('utf-8')
    
    @staticmethod
    def generate_nonce():
        """Generate a cryptographic nonce (number used once)"""
        return get_random_bytes(16).hex()
    
    @staticmethod
    def generate_timestamp_nonce():
        """Generate a timestamp-based nonce for replay attack prevention"""
        timestamp = int(time.time() * 1000)  # milliseconds
        random_part = get_random_bytes(8).hex()
        return f"{timestamp}:{random_part}"
    
    @staticmethod
    def verify_timestamp_nonce(nonce, max_age_seconds=60):
        """Verify timestamp nonce is not too old (prevents replay attacks)"""
        try:
            timestamp_str, _ = nonce.split(':')
            timestamp = int(timestamp_str)
            current_time = int(time.time() * 1000)
            age_ms = current_time - timestamp
            return age_ms >= 0 and age_ms <= (max_age_seconds * 1000)
        except:
            return False
    
    @staticmethod
    def sign_data(private_key_pem, data):
        """Sign data with RSA private key for authentication"""
        private_key = RSA.import_key(private_key_pem)
        hash_obj = SHA256.new(data.encode('utf-8') if isinstance(data, str) else data)
        from Crypto.Signature import pkcs1_15
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return signature
    
    @staticmethod
    def verify_signature(public_key_pem, data, signature):
        """Verify RSA signature"""
        try:
            public_key = RSA.import_key(public_key_pem)
            hash_obj = SHA256.new(data.encode('utf-8') if isinstance(data, str) else data)
            from Crypto.Signature import pkcs1_15
            pkcs1_15.new(public_key).verify(hash_obj, signature)
            return True
        except:
            return False

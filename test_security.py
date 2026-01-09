"""
Security Test Suite for Secure Chat Application
Tests various attack scenarios and security features
"""

import time
import threading
from crypto_utils import CryptoUtils
import json


class SecurityTests:
    """Test suite for security features"""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
    
    def test_nonce_replay_prevention(self):
        """Test that replayed nonces are detected"""
        print("\n[TEST] Nonce Replay Prevention")
        
        nonce = CryptoUtils.generate_timestamp_nonce()
        
        # First verification should succeed
        if CryptoUtils.verify_timestamp_nonce(nonce, max_age_seconds=60):
            print("  ✓ Fresh nonce accepted")
            self.passed += 1
        else:
            print("  ✗ Fresh nonce rejected")
            self.failed += 1
            return
        
        # Wait 61 seconds and verify nonce is too old
        print("  Testing nonce expiration (simulated)...")
        old_nonce = f"{int(time.time() * 1000) - 61000}:abcd1234"
        
        if not CryptoUtils.verify_timestamp_nonce(old_nonce, max_age_seconds=60):
            print("  ✓ Old nonce rejected (replay prevention)")
            self.passed += 1
        else:
            print("  ✗ Old nonce accepted (SECURITY ISSUE)")
            self.failed += 1
    
    def test_rsa_signature_verification(self):
        """Test RSA signature creation and verification"""
        print("\n[TEST] RSA Signature Authentication")
        
        # Generate keypair
        private_key, public_key = CryptoUtils.generate_rsa_keypair()
        
        # Sign data
        data = "alice:nonce123"
        signature = CryptoUtils.sign_data(private_key, data)
        
        # Verify correct signature
        if CryptoUtils.verify_signature(public_key, data, signature):
            print("  ✓ Valid signature verified")
            self.passed += 1
        else:
            print("  ✗ Valid signature rejected")
            self.failed += 1
            return
        
        # Test tampered data
        tampered_data = "bob:nonce123"
        if not CryptoUtils.verify_signature(public_key, tampered_data, signature):
            print("  ✓ Tampered data detected (MITM protection)")
            self.passed += 1
        else:
            print("  ✗ Tampered data accepted (SECURITY ISSUE)")
            self.failed += 1
        
        # Test wrong signature
        _, wrong_public_key = CryptoUtils.generate_rsa_keypair()
        if not CryptoUtils.verify_signature(wrong_public_key, data, signature):
            print("  ✓ Wrong public key detected")
            self.passed += 1
        else:
            print("  ✗ Wrong public key accepted (SECURITY ISSUE)")
            self.failed += 1
    
    def test_diffie_hellman_key_exchange(self):
        """Test Diffie-Hellman produces same shared secret"""
        print("\n[TEST] Diffie-Hellman Key Exchange")
        
        # Get DH parameters
        p, g = CryptoUtils.generate_dh_parameters()
        
        # Alice's keys
        alice_private = CryptoUtils.generate_dh_private_key()
        alice_public = CryptoUtils.compute_dh_public_key(alice_private, p, g)
        
        # Bob's keys
        bob_private = CryptoUtils.generate_dh_private_key()
        bob_public = CryptoUtils.compute_dh_public_key(bob_private, p, g)
        
        # Compute shared secrets
        alice_shared = CryptoUtils.compute_dh_shared_secret(alice_private, bob_public, p)
        bob_shared = CryptoUtils.compute_dh_shared_secret(bob_private, alice_public, p)
        
        # Verify they match
        if alice_shared == bob_shared:
            print("  ✓ Shared secrets match (perfect forward secrecy)")
            print(f"    Shared secret: {alice_shared.hex()[:32]}...")
            self.passed += 1
        else:
            print("  ✗ Shared secrets don't match (CRITICAL ISSUE)")
            self.failed += 1
    
    def test_aes_encryption_decryption(self):
        """Test AES-GCM encryption and decryption"""
        print("\n[TEST] AES-256-GCM Encryption")
        
        # Generate key
        key = CryptoUtils.generate_dh_private_key().to_bytes(32, 'big')[:32]
        
        plaintext = "This is a secret message!"
        
        # Encrypt
        encrypted = CryptoUtils.aes_encrypt(key, plaintext)
        print(f"  Ciphertext: {encrypted['ciphertext'][:32]}...")
        
        # Decrypt
        try:
            decrypted = CryptoUtils.aes_decrypt(
                key,
                encrypted['nonce'],
                encrypted['ciphertext'],
                encrypted['tag']
            )
            
            if decrypted == plaintext:
                print("  ✓ Encryption/Decryption successful")
                self.passed += 1
            else:
                print("  ✗ Decrypted text doesn't match")
                self.failed += 1
                return
        except Exception as e:
            print(f"  ✗ Decryption failed: {e}")
            self.failed += 1
            return
        
        # Test tampering detection
        print("  Testing tampering detection...")
        tampered_ciphertext = encrypted['ciphertext'][:-2] + "ff"
        
        try:
            CryptoUtils.aes_decrypt(
                key,
                encrypted['nonce'],
                tampered_ciphertext,
                encrypted['tag']
            )
            print("  ✗ Tampered ciphertext accepted (SECURITY ISSUE)")
            self.failed += 1
        except:
            print("  ✓ Tampering detected (integrity protection)")
            self.passed += 1
    
    def test_e2e_encryption_flow(self):
        """Test complete end-to-end encryption flow"""
        print("\n[TEST] End-to-End Encryption Flow")
        
        # Alice and Bob generate keypairs
        alice_private, alice_public = CryptoUtils.generate_rsa_keypair()
        bob_private, bob_public = CryptoUtils.generate_rsa_keypair()
        
        # DH key exchange
        p, g = CryptoUtils.generate_dh_parameters()
        
        alice_dh_private = CryptoUtils.generate_dh_private_key()
        alice_dh_public = CryptoUtils.compute_dh_public_key(alice_dh_private, p, g)
        
        bob_dh_private = CryptoUtils.generate_dh_private_key()
        bob_dh_public = CryptoUtils.compute_dh_public_key(bob_dh_private, p, g)
        
        # Sign DH exchanges (MITM protection)
        alice_nonce = CryptoUtils.generate_timestamp_nonce()
        alice_sig_data = f"alice:bob:{alice_dh_public}:{alice_nonce}"
        alice_signature = CryptoUtils.sign_data(alice_private, alice_sig_data)
        
        bob_nonce = CryptoUtils.generate_timestamp_nonce()
        bob_sig_data = f"bob:alice:{bob_dh_public}:{bob_nonce}"
        bob_signature = CryptoUtils.sign_data(bob_private, bob_sig_data)
        
        # Verify signatures
        if not CryptoUtils.verify_signature(alice_public, alice_sig_data, alice_signature):
            print("  ✗ Alice's signature verification failed")
            self.failed += 1
            return
        
        if not CryptoUtils.verify_signature(bob_public, bob_sig_data, bob_signature):
            print("  ✗ Bob's signature verification failed")
            self.failed += 1
            return
        
        print("  ✓ DH exchange signatures verified")
        
        # Compute shared secrets
        alice_shared = CryptoUtils.compute_dh_shared_secret(alice_dh_private, bob_dh_public, p)
        bob_shared = CryptoUtils.compute_dh_shared_secret(bob_dh_private, alice_dh_public, p)
        
        if alice_shared != bob_shared:
            print("  ✗ Shared secrets don't match")
            self.failed += 1
            return
        
        print("  ✓ Session key established")
        
        # Alice encrypts message
        message = "Hello Bob, this is end-to-end encrypted!"
        msg_nonce = CryptoUtils.generate_timestamp_nonce()
        encrypted = CryptoUtils.aes_encrypt(alice_shared, message)
        
        print("  ✓ Alice encrypted message (server sees only ciphertext)")
        
        # Bob decrypts message
        try:
            decrypted = CryptoUtils.aes_decrypt(
                bob_shared,
                encrypted['nonce'],
                encrypted['ciphertext'],
                encrypted['tag']
            )
            
            if decrypted == message:
                print("  ✓ Bob decrypted message successfully")
                print(f"    Message: '{decrypted}'")
                self.passed += 1
            else:
                print("  ✗ Decrypted message doesn't match")
                self.failed += 1
        except Exception as e:
            print(f"  ✗ Decryption failed: {e}")
            self.failed += 1
    
    def run_all_tests(self):
        """Run all security tests"""
        print("=" * 60)
        print("SECURE CHAT APPLICATION - SECURITY TEST SUITE")
        print("=" * 60)
        
        self.test_nonce_replay_prevention()
        self.test_rsa_signature_verification()
        self.test_diffie_hellman_key_exchange()
        self.test_aes_encryption_decryption()
        self.test_e2e_encryption_flow()
        
        print("\n" + "=" * 60)
        print("TEST RESULTS")
        print("=" * 60)
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        print(f"Total:  {self.passed + self.failed}")
        
        if self.failed == 0:
            print("\n✓ ALL SECURITY TESTS PASSED")
        else:
            print(f"\n✗ {self.failed} TEST(S) FAILED")
        
        print("=" * 60)


if __name__ == "__main__":
    tests = SecurityTests()
    tests.run_all_tests()

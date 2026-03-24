"""
Tests for the double-layer encryption (AES-GCM + ChaCha20-Poly1305)
and DEK/KEK key wrapping module.
"""
import os

from django.test import TestCase
from cryptography.exceptions import InvalidTag
from crypto.double_encrypt import (
    derive_kek, split_dek, double_encrypt, double_decrypt, rewrap_dek,
)


class DoubleEncryptTests(TestCase):

    def test_roundtrip(self):
        kek = os.urandom(32)
        plaintext = b"BlindBit SSE double encryption test"
        record = double_encrypt(plaintext, kek)
        result = double_decrypt(record, kek)
        self.assertEqual(result, plaintext)

    def test_unique_dek_per_file(self):
        kek = os.urandom(32)
        r1 = double_encrypt(b"same content", kek)
        r2 = double_encrypt(b"same content", kek)
        self.assertNotEqual(r1["encrypted_dek"], r2["encrypted_dek"])
        self.assertNotEqual(r1["ciphertext"], r2["ciphertext"])

    def test_rewrap_allows_decrypt_with_new_kek(self):
        old_kek = os.urandom(32)
        new_kek = os.urandom(32)
        plaintext = b"rewrap test"
        record = double_encrypt(plaintext, old_kek)
        updated = rewrap_dek(record, old_kek, new_kek)
        result = double_decrypt(updated, new_kek)
        self.assertEqual(result, plaintext)

    def test_rewrap_does_not_touch_ciphertext(self):
        old_kek = os.urandom(32)
        new_kek = os.urandom(32)
        record = double_encrypt(b"unchanged blob", old_kek)
        updated = rewrap_dek(record, old_kek, new_kek)
        self.assertEqual(record["ciphertext"], updated["ciphertext"])
        self.assertEqual(record["iv_aes"], updated["iv_aes"])
        self.assertEqual(record["nonce_cc"], updated["nonce_cc"])

    def test_wrong_kek_raises_invalid_tag(self):
        kek_a = os.urandom(32)
        kek_b = os.urandom(32)
        record = double_encrypt(b"secret", kek_a)
        with self.assertRaises(InvalidTag):
            double_decrypt(record, kek_b)

    def test_split_dek_subkeys_differ(self):
        dek = os.urandom(32)
        dek_a, dek_b = split_dek(dek)
        self.assertNotEqual(dek_a, dek_b)
        self.assertEqual(len(dek_a), 32)
        self.assertEqual(len(dek_b), 32)

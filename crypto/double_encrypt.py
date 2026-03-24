"""
Double-Layer Encryption — AES-GCM (inner) + ChaCha20-Poly1305 (outer)
with DEK/KEK key wrapping for password-change resilience.

Functions:
    derive_kek      — Argon2id KDF: password + salt → 32-byte KEK
    split_dek       — HMAC-SHA256 domain separation into two subkeys
    double_encrypt  — encrypt plaintext with double layer, wrap DEK
    double_decrypt  — unwrap DEK, decrypt both layers
    rewrap_dek      — re-wrap DEK under a new KEK (no ciphertext change)
"""

import os
import hmac
import hashlib

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def derive_kek(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte KEK from password using Argon2id.

    Args:
        password: The user's plaintext password.
        salt: A 16-byte random salt unique to each user.

    Returns:
        A 32-byte Key Encryption Key.
    """
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )


def split_dek(dek: bytes) -> tuple[bytes, bytes]:
    """Split DEK into two subkeys via HMAC-SHA256.

    Uses domain-separated HMAC so each layer gets an independent
    cryptographic key derived from the same DEK.

    Args:
        dek: A 32-byte Data Encryption Key.

    Returns:
        (dek_a, dek_b) — 32-byte subkeys for AES-GCM and ChaCha20 respectively.
    """
    dek_a = hmac.new(dek, b"layer-aes-gcm", hashlib.sha256).digest()
    dek_b = hmac.new(dek, b"layer-chacha20-poly", hashlib.sha256).digest()
    return dek_a, dek_b


def double_encrypt(plaintext: bytes, kek: bytes) -> dict:
    """Encrypt with AES-GCM then ChaCha20-Poly1305, wrap DEK with KEK.

    1. Generate a random 32-byte DEK.
    2. Split DEK into two subkeys (dek_a for AES-GCM, dek_b for ChaCha20).
    3. Inner layer: AES-256-GCM(dek_a, plaintext).
    4. Outer layer: ChaCha20-Poly1305(dek_b, inner_ciphertext).
    5. Wrap DEK with KEK using AES-GCM.

    Args:
        plaintext: Raw bytes to encrypt.
        kek: 32-byte Key Encryption Key (derived from user password).

    Returns:
        Dict with keys: ciphertext, iv_aes, nonce_cc, encrypted_dek, kek_iv.
    """
    dek = os.urandom(32)
    dek_a, dek_b = split_dek(dek)

    # Inner layer — AES-GCM
    iv_aes = os.urandom(12)
    inner = AESGCM(dek_a).encrypt(iv_aes, plaintext, None)

    # Outer layer — ChaCha20-Poly1305
    nonce_cc = os.urandom(12)
    outer = ChaCha20Poly1305(dek_b).encrypt(nonce_cc, inner, None)

    # Wrap DEK with KEK
    kek_iv = os.urandom(12)
    encrypted_dek = AESGCM(kek).encrypt(kek_iv, dek, None)

    return {
        "ciphertext": outer,
        "iv_aes": iv_aes,
        "nonce_cc": nonce_cc,
        "encrypted_dek": encrypted_dek,
        "kek_iv": kek_iv,
    }


def double_decrypt(record: dict, kek: bytes) -> bytes:
    """Decrypt ChaCha20 outer layer then AES-GCM inner layer.

    1. Unwrap DEK from KEK.
    2. Split DEK into subkeys.
    3. Decrypt outer ChaCha20-Poly1305 layer.
    4. Decrypt inner AES-GCM layer.

    Args:
        record: Dict with keys: ciphertext, iv_aes, nonce_cc, encrypted_dek, kek_iv.
        kek: 32-byte Key Encryption Key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If KEK is wrong or data tampered.
    """
    dek = AESGCM(kek).decrypt(record["kek_iv"], record["encrypted_dek"], None)
    dek_a, dek_b = split_dek(dek)
    inner = ChaCha20Poly1305(dek_b).decrypt(record["nonce_cc"], record["ciphertext"], None)
    plaintext = AESGCM(dek_a).decrypt(record["iv_aes"], inner, None)
    return plaintext


def rewrap_dek(record: dict, old_kek: bytes, new_kek: bytes) -> dict:
    """Re-wrap DEK for new KEK without touching ciphertext.

    Used during password changes: the encrypted file data and its
    IVs/nonces remain unchanged — only the DEK wrapper is updated.

    Args:
        record: Dict with at least: encrypted_dek, kek_iv (plus other fields).
        old_kek: Current 32-byte KEK (from old password).
        new_kek: New 32-byte KEK (from new password).

    Returns:
        Updated record dict with new encrypted_dek and kek_iv.
        ciphertext, iv_aes, nonce_cc are NEVER modified.
    """
    dek = AESGCM(old_kek).decrypt(record["kek_iv"], record["encrypted_dek"], None)
    new_kek_iv = os.urandom(12)
    new_enc_dek = AESGCM(new_kek).encrypt(new_kek_iv, dek, None)
    return {
        **record,
        "encrypted_dek": new_enc_dek,
        "kek_iv": new_kek_iv,
        # ciphertext, iv_aes, nonce_cc are NEVER modified
    }

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, plaintext, associated_data):
    """
    Encrypts the plaintext using AES GCM mode.

    Args:
        key (bytes): The encryption key.
        plaintext (bytes): The data to encrypt.
        associated_data (bytes): Additional data to authenticate but not encrypt.

    Returns:
        tuple: A tuple containing the nonce and the ciphertext.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return (nonce, ciphertext)

def decrypt(key, nonce, ciphertext, associated_data):
    """
    Decrypts the ciphertext using AES GCM mode.

    Args:
        key (bytes): The decryption key.
        nonce (bytes): The nonce used during encryption.
        ciphertext (bytes): The data to decrypt.
        associated_data (bytes): The associated data used during encryption.

    Returns:
        bytes: The decrypted plaintext.
    """
    aesgcm = AESGCM(key)
    # raise Exception("nonce:", nonce, "ciphertext:", ciphertext, "key:", key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

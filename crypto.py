import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # OWASP A2, secure key derivaiton
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # OWASP A3, authenticated encryption


def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:  # OWASP A2, strong kdf parameters
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())


def encrypt(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(16)  # Cryptographically secure random salt
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Size for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def decrypt(data: bytes, password: str) -> bytes:
    if len(data) < 28:  # Integrity check (OWASP A6)
        raise ValueError("Encrypted data is too short")
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

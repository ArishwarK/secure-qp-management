import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import MASTER_KEY

def encrypt_question_paper(plain_text: str) -> dict:
    """
    Encrypts question paper using AES-256-GCM.
    Returns base64 encoded ciphertext, nonce, and auth tag implicitly verified by GCM.
    """
    # 256-bit AES Key
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)  # Standard 96-bit nonce for GCM
    
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode('utf-8'), None)
    
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_question_paper(ciphertext_b64: str, nonce_b64: str) -> str:
    """
    Decrypts AES-256-GCM encrypted payload.
    Raises an error if ciphertext or nonce is tampered with.
    """
    aesgcm = AESGCM(MASTER_KEY)
    nonce = base64.b64decode(nonce_b64.encode('utf-8'))
    ciphertext = base64.b64decode(ciphertext_b64.encode('utf-8'))
    
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_bytes.decode('utf-8')
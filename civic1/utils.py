from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import os
from django.conf import settings

# Load private key once (at module level)
private_key_path = os.path.join(settings.BASE_DIR, 'keys', 'private_key.pem')
with open(private_key_path, 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

def decrypt_email(encrypted_email_hex):
    encrypted_bytes = bytes.fromhex(encrypted_email_hex)
    decrypted_email = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_email.decode()

import os
from django.conf import settings
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Load public key for encryption
public_key_path = os.path.join(settings.BASE_DIR, 'keys', 'public_key.pem')
with open(public_key_path, 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read())

# Load private key for decryption
private_key_path = os.path.join(settings.BASE_DIR, 'keys', 'private_key.pem')
with open(private_key_path, 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

def encrypt_candidate_id(candidate_id):
    candidate_bytes = str(candidate_id).encode()
    encrypted = public_key.encrypt(
        candidate_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted.hex()

def decrypt_candidate_id(encrypted_hex):
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return int(decrypted.decode())

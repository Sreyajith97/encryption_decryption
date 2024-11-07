from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

# AES Encryption and Decryption
def aes_encrypt(plaintext, key):
    iv = b'0123456789abcdef'  # Initialization Vector (16 bytes)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad plaintext to be a multiple of 16 bytes
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + chr(padding_length) * padding_length
    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key):
    iv = b'0123456789abcdef'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]
    return decrypted_data.decode('utf-8')

# RSA Encryption and Decryption
def rsa_encrypt(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Caesar Cipher Encryption and Decryption
def caesar_encrypt(plaintext, shift):
    encrypted = ''.join(
        chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else
        chr((ord(char) - 97 + shift) % 26 + 97) if char.islower() else char
        for char in plaintext
    )
    return encrypted

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

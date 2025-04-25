from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# XOR de bytes
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Standard AES Encryption for Operation Modes Implementation (128 bits)
def aes_encrypt(key, plaintext):
    # Criação de um objeto Cipher com IV vazio
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encripta o plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def aes_decrypt(key, ciphertext):
    # Criação de um objeto Cipher com IV vazio
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Desencripta o ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

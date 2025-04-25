from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# XOR de bytes
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Standard AES Encryption for Operation Modes Implementation (128 bits)
def aes_encrypt(key, plaintext):
    # Criação de um objeto Cipher com IV vazio
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Adiciona padding ao plaintext para que ele tenha o tamanho correto
    # O tamanho do bloco AES é 16 bytes (128 bits)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encripta o plaintext
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def aes_decrypt(key, ciphertext):
    # Criação de um objeto Cipher com IV vazio
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Desencripta o ciphertext
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext
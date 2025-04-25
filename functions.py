from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import time

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

# Função auxiliar para medir tempo e executar criptografia/descriptografia
def eficiency(mode_name, encrypt_func, decrypt_func, *args):
    start_time = time.time()
    ciphertext = encrypt_func(*args)
    encryption_time = time.time() - start_time

    start_time = time.time()
    decrypted = decrypt_func(ciphertext, *args)

    # Remover padding manualmente
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted) + unpadder.finalize()

    decryption_time = time.time() - start_time

    print(f'{mode_name} Ciphertext (Base64): {base64.b64encode(ciphertext).decode()}')
    print(f'{mode_name} Decrypted: {decrypted.decode()}')
    print(f'{mode_name} Encryption Time: {encryption_time:.6f} seconds')
    print(f'{mode_name} Decryption Time: {decryption_time:.6f} seconds\n')
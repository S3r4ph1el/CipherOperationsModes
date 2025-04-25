from cryptography.hazmat.primitives import padding
from cbc import CBC
from cfb import CFB
from ofb import OFB
from ctr import CTR
from ecb import ECB
import os
import base64
import time

def main():
    # Chave de 16 bytes (128 bits)
    key = os.urandom(16)
    iv = os.urandom(16)  # IV para CBC, CFB e OFB
    nonce = os.urandom(8)  # Nonce para CTR

    # Solicitar entrada do usuário
    plaintext = input("Digite o texto para criptografar: ").encode()

    # Adicionar padding ao plaintext (PKCS7)
    padder = padding.PKCS7(128).padder()
    plaintext_padded = padder.update(plaintext) + padder.finalize()

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

    # ECB
    ecb = ECB(key, plaintext)
    eficiency("ECB", ecb.encrypt, ecb.decrypt)

    # CBC
    cbc = CBC(key, iv, plaintext)
    eficiency("CBC", cbc.encrypt, cbc.decrypt)

    # CFB
    cfb = CFB(key, iv, plaintext)
    eficiency("CFB", cfb.encrypt, cfb.decrypt)
    
    # OFB
    ofb = OFB(key, iv, plaintext_padded)
    eficiency("OFB", ofb.encrypt, ofb.decrypt)

    # CTR
    ctr = CTR(key, nonce, plaintext_padded)
    eficiency("CTR", ctr.encrypt, ctr.decrypt)

if __name__ == "__main__":
    main()

# Este código é um exemplo de implementação de diferentes modos de operação de criptografia simétrica AES (ECB, CBC, CFB, OFB e CTR)
# em Python. Ele mede o tempo de criptografia e descriptografia para cada modo e exibe os resultados em Base64.

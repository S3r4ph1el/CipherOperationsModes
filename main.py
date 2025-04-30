from cryptography.hazmat.primitives import padding
from functions import eficiency
from cbc import CBC
from cfb import CFB
from ofb import OFB
from ctr import CTR
from ecb import ECB
import os

def main():
    # Chave de 16 bytes (128 bits)
    key = os.urandom(16)
    iv = os.urandom(16)  # IV para CBC, CFB e OFB
    nonce = os.urandom(8)  # Nonce para CTR

    print("Chave: 0x", key.hex())
    print("IV: 0x", iv.hex())
    print("Nonce: 0x", nonce.hex())
    print("\n")

    # Solicitar entrada do usuário
    plaintext = input("Digite o texto para criptografar: ").encode()
    print("\n")

    # Adicionar padding ao plaintext (PKCS7)
    padder = padding.PKCS7(128).padder()
    plaintext_padded = padder.update(plaintext) + padder.finalize()

    # ECB
    ecb = ECB(key, plaintext_padded)
    eficiency("ECB", ecb.encrypt, ecb.decrypt)

    # CBC
    cbc = CBC(key, iv, plaintext_padded)
    eficiency("CBC", cbc.encrypt, cbc.decrypt)

    # CFB
    cfb = CFB(key, iv, plaintext_padded)
    eficiency("CFB", cfb.encrypt, cfb.decrypt)
    
    # OFB
    ofb = OFB(key, iv, plaintext_padded)
    eficiency("OFB", ofb.encrypt, ofb.decrypt)

    # CTR
    ctr = CTR(key, plaintext_padded, nonce)
    eficiency("CTR", ctr.encrypt, ctr.decrypt)

if __name__ == "__main__":
    main()

# Este código é um exemplo de implementação de diferentes modos de operação de criptografia simétrica AES (ECB, CBC, CFB, OFB e CTR)
# em Python. Ele mede o tempo de criptografia e descriptografia para cada modo e exibe os resultados em Base64.

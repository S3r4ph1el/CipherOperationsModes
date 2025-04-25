from functions import aes_encrypt, xor_bytes
import os

# OFB Mode
class OFB:
    def __init__(self, key, nonce, plaintext):
        self.key = key
        self.nonce = nonce
        self.plaintext = plaintext

    def encrypt(self):
        ciphertext = b''
        temp = self.nonce

        for i in range(0, len(self.plaintext), 16):
            # Cifra o bloco com o nonce ou o último bloco cifrado
            block = self.plaintext[i:i+16]
            encrypted_block = aes_encrypt(self.key, temp)
            temp = encrypted_block

            # Concatena o ciphertext com o resultado do XOR
            ciphertext += xor_bytes(block, encrypted_block)

        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = b''
        temp = self.nonce
        for i in range(0, len(ciphertext), 16):
            # Cifra o bloco com o nonce ou o último bloco cifrado
            block = ciphertext[i:i+16]
            encrypted_block = aes_encrypt(self.key, temp)
            temp = encrypted_block

            # Concatena o plaintext com o resultado do XOR
            plaintext += xor_bytes(block, encrypted_block)

        return plaintext
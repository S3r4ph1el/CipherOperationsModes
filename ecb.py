from functions import aes_encrypt, aes_decrypt
import os

# ECB Mode
class ECB:
    def __init__(self, key, plaintext):
        self.key = key
        self.plaintext = plaintext

    def encrypt(self):
        ciphertext = b''

        # Separa o plainText em blocos e aplica a cifra AES em cada bloco manualmente
        for i in range(0, len(self.plaintext), 16):
            block = self.plaintext[i:i+16]
            encrypted_block = aes_encrypt(self.key, block)
            ciphertext += encrypted_block

        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = b''

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = aes_decrypt(self.key, block)
            plaintext += decrypted_block

        return plaintext
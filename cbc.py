from functions import aes_encrypt, aes_decrypt, xor_bytes
import os

# CBC Mode
class CBC:
    def __init__(self, key, iv, plaintext):
        self.key = key
        self.iv = iv
        self.plaintext = plaintext

    def encrypt(self):
        ciphertext = b''
        temp = self.iv

        for i in range(0, len(self.plaintext), 16):
            block = self.plaintext[i:i+16]
            block = xor_bytes(block, temp)
            encrypted_block = aes_encrypt(self.key, block)
            ciphertext += encrypted_block
            temp = encrypted_block

        return ciphertext

    def decrypt(self, ciphertext):
        temp = self.iv
        plaintext = b''

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = aes_decrypt(self.key, block)
            decrypted_block = xor_bytes(decrypted_block, temp)
            plaintext += decrypted_block
            temp = block

        return plaintext
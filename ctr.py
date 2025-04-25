from functions import aes_encrypt, xor_bytes
import os

# CTR Mode
class CTR:
    def __init__(self, key, plaintext, nonce):
        self.key = key
        self.plaintext = plaintext
        self.nonce = nonce

    def encrypt(self):
        ciphertext = b''
        counter = 1

        for i in range(0, len(self.plaintext), 16):
            # Formatar o bloco com o nonce e o contador
            counter_block = self.nonce + counter.to_bytes(8, 'big')

            # Cifra o bloco com a key e o bloco do contador
            encrypted_block = aes_encrypt(self.key, counter_block)

            # Seleciona o número correto de bytes
            block = self.plaintext[i:i+16]

            # Concatena o block com o resultado do XOR
            ciphertext += xor_bytes(block, encrypted_block)
            counter += 1

        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = b''
        counter = 1

        for i in range(0, len(ciphertext), 16):
            # Formatar o bloco com o nonce e o contador
            counter_block = self.nonce + counter.to_bytes(8, 'big')

            # Cifra o bloco com a key e o bloco do contador
            encrypted_block = aes_encrypt(self.key, counter_block)

            block = ciphertext[i:i+16]

            # Concatena o plaintext com o resultado do XOR
            plaintext += xor_bytes(block, encrypted_block)
            counter += 1

        return plaintext
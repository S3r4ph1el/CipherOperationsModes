from functions import aes_encrypt, xor_bytes
import os

# CFB Mode
class CFB:
    def __init__(self, key, iv, plaintext):
        self.key = key
        self.iv = iv
        self.plaintext = plaintext

    def encrypt(self):
        ciphertext = b''
        register = bytearray(self.iv) # Inicializa o registro com o IV

        for i in range(0, len(self.plaintext), 16):
            # Cifra o bloco de 16 bytes com o IV ou o último bloco cifrado
            block = self.plaintext[i:i+16]
            encrypted_block = aes_encrypt(self.key, register)

            # Seleciona o número correto de bytes
            selection = encrypted_block[:len(block)]

            # Cifra o bloco com os bytes selecionados
            cipher_block = xor_bytes(block, selection)
            ciphertext += cipher_block

            # Atualiza o registro com o último bloco cifrado
            register = register[16:] + bytearray(cipher_block)

        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = b''
        register = bytearray(self.iv)

        for i in range(0, len(ciphertext), 16):
            # Cifra o bloco de 16 bytes com o IV ou o último bloco cifrado
            block = ciphertext[i:i+16]
            encrypted_block = aes_encrypt(self.key, register)

            # Seleciona o número correto de bytes
            selection = encrypted_block[:len(block)]

            # Cifra o bloco com os bytes selecionados
            plain_block = xor_bytes(block, selection)
            plaintext += plain_block

            # Atualiza o registro com o último bloco cifrado
            register = register[16:] + bytearray(block)

        return plaintext
import ctypes
import os
import sys

from aes import encrypt, decrypt


# Load the shared object file
rijndael = ctypes.CDLL('./rijndael.so')

# Define the block size
BLOCK_SIZE = 16

# Function to generate a random key
def generate_random_key():
    return os.urandom(BLOCK_SIZE)

# Function to generate a random plaintext
def generate_random_plaintext():
    return os.urandom(BLOCK_SIZE)

# Function to compare two blocks of data
def compare_blocks(block1, block2):
    return block1 == block2

# Main unit test function
def unit_test():
    for i in range(3):
        print("Test number " + str(i + 1) + ":")

        # Generate random key and plaintext
        key = generate_random_key()
        plaintext = generate_random_plaintext()

        # Convert key and plaintext to ctypes buffers
        key_buffer = ctypes.create_string_buffer(key)
        plaintext_buffer = ctypes.create_string_buffer(plaintext)

        # Encrypt with C implementation
        ciphertext_c = ctypes.create_string_buffer(BLOCK_SIZE)
        ciphertext_c = ctypes.string_at(
            rijndael.aes_encrypt_block(plaintext_buffer, key_buffer), 
            16
        )
        # Decrypt with C implementation
        decryptedtext_c = ctypes.create_string_buffer(BLOCK_SIZE)
        decryptedtext_c = ctypes.string_at(
            rijndael.aes_decrypt_block(ciphertext_c, key_buffer), 
            16
        )

        # Encrypt with Python implementation
        ciphertext_python = encrypt(key, plaintext)
        # Decrypt with Python implementation
        decryptedtext_python = decrypt(key, ciphertext_python)

        # Check if ciphertexts match
        if not compare_blocks(ciphertext_c.raw, ciphertext_python):
            print("Error: Ciphertexts do not match!")
            sys.exit(1)

        # Check if decrypted texts match
        if not compare_blocks(decryptedtext_c.raw, decryptedtext_python):
            print("Error: Decrypted texts do not match!")
            sys.exit(1)

    print("Unit test passed!")


if __name__ == "__main__":
    unit_test()

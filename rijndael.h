/*
 * Name: David Santamaria Torres
 * Student Number: D23124831
 * Description: This is a header file for implementing the AES algorithm. It
 * includes the two main function declarations related to encryption and
 * decryption operations, which are the main entry points for encrypting and
 * decrypting data. The header file also defines macros and constants related to
 * block size and block access.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif

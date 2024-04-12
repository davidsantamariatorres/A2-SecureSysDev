/*
 * Name: David Santamaria Torres
 * Student Number: D23124831
 * Description: This code implements the AES algorithm for encrypting and
 * decrypting data. It provides functions for substitution, shifting rows,
 * mixing columns, adding round keys, and key expansion. The aes_encrypt_block
 * function encrypts a block of plaintext, while aes_decrypt_block decrypts a
 * block of ciphertext.
 */

#include "rijndael.h"

#include <stdlib.h>
#include <string.h>

// S-box lookup table
unsigned char s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
};

// Inverse S-box lookup table
unsigned char inv_s_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
    0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32,
    0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49,
    0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
    0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05,
    0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41,
    0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
    0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
    0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
    0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0C, 0x7D,
};

// Round constant lookup table
const unsigned char rcon[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                              0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
                              0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
                              0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39};

/*
 * Operations used when encrypting a block
 */

// This function performs the SubBytes operation by substituting each byte in
// the block with its corresponding value
void sub_bytes(unsigned char *block) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    block[i] = s_box[block[i]];
  }
}

// Function responsible for performing a row-wise shifting operation on the
// input block
void shift_rows(unsigned char *block) {
  unsigned char temp;

  // Shift second row
  temp = block[1];
  block[1] = block[5];
  block[5] = block[9];
  block[9] = block[13];
  block[13] = temp;

  // Shift third row
  temp = block[2];
  block[2] = block[10];
  block[10] = temp;
  temp = block[6];
  block[6] = block[14];
  block[14] = temp;

  // Shift fourth row
  temp = block[15];
  block[15] = block[11];
  block[11] = block[7];
  block[7] = block[3];
  block[3] = temp;
}

unsigned char xtime(unsigned char x) {
  return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

// This function performs the MixColumns operation on a single column
void mix_single_column(unsigned char *a) {
  unsigned char t = a[0] ^ a[1] ^ a[2] ^ a[3];
  unsigned char u = a[0];
  a[0] ^= t ^ xtime(a[0] ^ a[1]);
  a[1] ^= t ^ xtime(a[1] ^ a[2]);
  a[2] ^= t ^ xtime(a[2] ^ a[3]);
  a[3] ^= t ^ xtime(a[3] ^ u);
}

// This function performs the MixColumns operation on the entire AES state
// matrix during encryption
void mix_columns(unsigned char *block) {
  for (int i = 0; i < 4; i++) {
    mix_single_column(block + i * 4);
  }
}

/*
 * Operations used when decrypting a block
 */

// This function performs the inverse SubBytes operation by substituting each
// byte in the block with its corresponding value from the inverse S-box lookup
// table
void invert_sub_bytes(unsigned char *block) {
  for (int i = 0; i < 16; i++) {
    block[i] = inv_s_box[block[i]];
  }
}

// This function performs the inverse ShiftRows operation by shifting the rows
// of the block in the opposite direction
void invert_shift_rows(unsigned char *block) {
  unsigned char temp;

  // Shift first row (no change)

  // Shift second row
  temp = block[1];
  block[1] = block[13];
  block[13] = block[9];
  block[9] = block[5];
  block[5] = temp;

  // Shift third row
  temp = block[2];
  block[2] = block[10];
  block[10] = temp;
  temp = block[6];
  block[6] = block[14];
  block[14] = temp;

  // Shift fourth row
  temp = block[3];
  block[3] = block[7];
  block[7] = block[11];
  block[11] = block[15];
  block[15] = temp;
}

// This function applies the inverse MixColumns operation to a block of bytes by
// performing a series of calculations on each column of the block. It then
// calls the mix_columns function to complete the inversion process.
void invert_mix_columns(unsigned char *block) {
  for (int i = 0; i < 4; i++) {
    unsigned char u = xtime(xtime(block[i * 4] ^ block[i * 4 + 2]));
    unsigned char v = xtime(xtime(block[i * 4 + 1] ^ block[i * 4 + 3]));
    block[i * 4] ^= u;
    block[i * 4 + 1] ^= v;
    block[i * 4 + 2] ^= u;
    block[i * 4 + 3] ^= v;
  }

  mix_columns(block);
}

/*
 * This operation is shared between encryption and decryption
 */

// This function performs the AddRoundKey operation in the AES encryption
// algorithm. It XORs each byte of the input block with the corresponding byte
// of the round key.
void add_round_key(unsigned char *block, unsigned char *round_key) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    block[i] ^= round_key[i];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  int key_size = BLOCK_SIZE;  // 128-bit key
  int num_rounds = 10;        // Number of rounds for AES-128
  int expanded_key_size =
      (num_rounds + 1) * key_size;  // Size of the expanded key

  unsigned char *expanded_key = (unsigned char *)malloc(expanded_key_size);
  if (expanded_key == NULL) {
    // Error: Memory allocation failed
    return NULL;
  }

  // Copy the original key to the beginning of the expanded key
  memcpy(expanded_key, cipher_key, key_size);

  // Key expansion algorithm
  int bytes_generated = key_size;
  unsigned char temp[4];

  while (bytes_generated < expanded_key_size) {
    // Copy the previous 4 bytes to temp
    memcpy(temp, &expanded_key[bytes_generated - 4], 4);

    // Perform key schedule core
    if (bytes_generated % key_size == 0) {
      // RotWord: left rotate the 4 bytes
      // SubWord: apply the S-box substitution to each byte
      // Rcon: XOR with a round constant (see AES key schedule)
      temp[0] = s_box[temp[1]] ^ rcon[bytes_generated / key_size];
      temp[1] = s_box[temp[2]];
      temp[2] = s_box[temp[3]];
      temp[3] = s_box[temp[0]];
    }

    // XOR temp with the 4-byte block n bytes before the new expanded key
    for (int i = 0; i < 4; i++) {
      expanded_key[bytes_generated] =
          expanded_key[bytes_generated - key_size] ^ temp[i];
      bytes_generated++;
    }
  }

  return expanded_key;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */

// This function encrypts a single block of plaintext using the AES encryption
// algorithm. It performs a series of operations on the input block, including
// SubBytes, ShiftRows, MixColumns, and AddRoundKey, to produce the ciphertext.
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  unsigned char *expanded_key = expand_key(key);
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);

  if (output == NULL) {
    // Error: Memory allocation failed
    free(expanded_key);
    return NULL;
  }

  memcpy(output, plaintext, BLOCK_SIZE);

  // Initial round
  add_round_key(output, expanded_key);

  // Main rounds
  for (int round = 1; round <= 10; round++) {
    // SubBytes
    sub_bytes(output);

    // ShiftRows
    shift_rows(output);

    // MixColumns (except for the last round)
    if (round < 10) {
      mix_columns(output);
    }

    // AddRoundKey
    add_round_key(output, expanded_key + round * BLOCK_SIZE);
  }

  free(expanded_key);

  return output;
}

// This function decrypts a single block of ciphertext using the AES decryption
// algorithm. It performs a series of operations on the input block, including
// Inverse ShiftRows, Inverse SubBytes, Inverse MixColumns, and AddRoundKey,
unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  unsigned char *expanded_key = expand_key(key);
  if (expanded_key == NULL) {
    // Error: Memory allocation failed
    return NULL;
  }

  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  if (output == NULL) {
    // Error: Memory allocation failed
    free(expanded_key);
    return NULL;
  }

  memcpy(output, ciphertext, BLOCK_SIZE);

  // Initial round
  add_round_key(output, expanded_key + 10 * BLOCK_SIZE);

  // Main rounds
  for (int round = 9; round >= 0; round--) {
    // Inverse ShiftRows
    invert_shift_rows(output);

    // Inverse SubBytes
    invert_sub_bytes(output);

    // AddRoundKey
    add_round_key(output, expanded_key + round * BLOCK_SIZE);

    // Inverse MixColumns (except for the first round)
    if (round > 0) {
      invert_mix_columns(output);
    }
  }

  free(expanded_key);

  return output;
}

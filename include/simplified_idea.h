
/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 * Purpose: Simplified IDEA encryption and decryption declarations.
 */

#ifndef SIMPLIFIED_IDEA_H
#define SIMPLIFIED_IDEA_H

#include <cstdint>

namespace simplified_idea {

constexpr int BLOCK_SIZE = 16;
constexpr int KEY_SIZE = 32;

// Encrypt one 16-bit block using a 32-bit key.
uint16_t encrypt(uint16_t plaintext, uint32_t key);

// Decrypt one 16-bit ciphertext block using the same key.
uint16_t decrypt(uint16_t ciphertext, uint32_t key);

}  // namespace simplified_idea

#endif

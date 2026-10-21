
/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 * Purpose: Simplified IDEA encryption and decryption declarations.
 */

#ifndef SIMPLIFIED_IDEA_H
#define SIMPLIFIED_IDEA_H

#include <array>
#include <cstdint>

namespace simplified_idea {

constexpr int BLOCK_SIZE = 16;
constexpr int KEY_SIZE = 32;

struct BlockTrace {
    std::array<std::array<uint8_t, 14>, 4> roundSteps{};
    std::array<std::array<uint8_t, 4>, 4> roundOutput{};
    std::array<uint8_t, 4> finalOutput{};
};

// Encrypt one 16-bit block using a 32-bit key.
uint16_t encrypt(uint16_t plaintext, uint32_t key,
                 BlockTrace* trace = nullptr);

// Decrypt one 16-bit ciphertext block using the same key.
uint16_t decrypt(uint16_t ciphertext, uint32_t key,
                 BlockTrace* trace = nullptr);

}  // namespace simplified_idea

#endif


/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 *
 * Simplified IDEA implementation.
 * Uses 16-bit blocks, a 32-bit key, four rounds,
 * and a final half-round transformation.
 */

#include "simplified_idea.h"

#include <array>
#include <stdexcept>

namespace simplified_idea {
namespace {

using Subkeys = std::array<uint8_t, 28>;

// Encryption S-box is not used by Simplified IDEA.
// Its operations are XOR, addition modulo 16,
// and multiplication modulo 17.

// Addition modulo 16.
uint8_t add16(uint8_t a, uint8_t b) {
    return static_cast<uint8_t>((a + b) & 0x0F);
}

// Subtraction modulo 16.
uint8_t sub16(uint8_t a, uint8_t b) {
    return static_cast<uint8_t>((a - b) & 0x0F);
}

// Multiplication modulo 17.
// The nibble 0000 represents 16 in multiplication.
uint8_t mul17(uint8_t a, uint8_t b) {
    const int x = (a == 0) ? 16 : a;
    const int y = (b == 0) ? 16 : b;
    const int result = (x * y) % 17;

    return static_cast<uint8_t>(result == 16 ? 0 : result);
}

// Multiplicative inverse modulo 17.
// Nibble zero represents 16, which is its own inverse.
uint8_t inverse17(uint8_t value) {
    const int x = (value == 0) ? 16 : value;

    for (int candidate = 1; candidate <= 16; ++candidate) {
        if ((x * candidate) % 17 == 1) {
            return static_cast<uint8_t>(
                candidate == 16 ? 0 : candidate);
        }
    }

    throw std::runtime_error("No multiplicative inverse found");
}

// Additive inverse modulo 16.
// uint8_t inverse16(uint8_t value) {
// return static_cast<uint8_t>((16 - value) & 0x0F);
// }

// Generate 28 four-bit subkeys.
// Rotate the complete 32-bit key left by six bits
// between groups of eight nibbles.
Subkeys generate_subkeys(uint32_t key) {
    Subkeys subkeys{};
    uint32_t rotated = key;
    int index = 0;

    while (index < static_cast<int>(subkeys.size())) {
        for (int shift = 28; shift >= 0 && index < 28;
             shift -= 4) {
            subkeys[index++] =
                static_cast<uint8_t>((rotated >> shift) & 0x0F);
        }

        rotated = (rotated << 6) | (rotated >> 26);
    }

    return subkeys;
}

// Process one complete encryption round.
void encrypt_round(std::array<uint8_t, 4>& x,
                   const Subkeys& k, int offset) {
    const uint8_t a = mul17(x[0], k[offset]);
    const uint8_t b = add16(x[1], k[offset + 1]);
    const uint8_t c = add16(x[2], k[offset + 2]);
    const uint8_t d = mul17(x[3], k[offset + 3]);

    const uint8_t e = a ^ c;
    const uint8_t f = b ^ d;
    const uint8_t g = mul17(e, k[offset + 4]);
    const uint8_t h = add16(f, g);
    const uint8_t i = mul17(h, k[offset + 5]);
    const uint8_t j = add16(g, i);

    // Round output order: steps 11, 13, 12, 14.
    x = {
        static_cast<uint8_t>(a ^ i),
        static_cast<uint8_t>(b ^ j),
        static_cast<uint8_t>(c ^ i),
        static_cast<uint8_t>(d ^ j)};
}

// Reverse one complete encryption round.
void decrypt_round(std::array<uint8_t, 4>& x,
                   const Subkeys& k, int offset) {
    // Recover the intermediate values in reverse order.
    const uint8_t e = x[0] ^ x[2];
    const uint8_t f = x[1] ^ x[3];
    const uint8_t g = mul17(e, k[offset + 4]);
    const uint8_t h = add16(f, g);
    const uint8_t i = mul17(h, k[offset + 5]);
    const uint8_t j = add16(g, i);

    const uint8_t a = x[0] ^ i;
    const uint8_t b = x[1] ^ j;
    const uint8_t c = x[2] ^ i;
    const uint8_t d = x[3] ^ j;

    // Undo the first four round operations.
    x = {
        mul17(a, inverse17(k[offset])),
        sub16(b, k[offset + 1]),
        sub16(c, k[offset + 2]),
        mul17(d, inverse17(k[offset + 3]))};
}

std::array<uint8_t, 4> split_block(uint16_t block) {
    return {
        static_cast<uint8_t>((block >> 12) & 0x0F),
        static_cast<uint8_t>((block >> 8) & 0x0F),
        static_cast<uint8_t>((block >> 4) & 0x0F),
        static_cast<uint8_t>(block & 0x0F)};
}

uint16_t join_block(const std::array<uint8_t, 4>& x) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(x[0]) << 12) |
        (static_cast<uint16_t>(x[1]) << 8) |
        (static_cast<uint16_t>(x[2]) << 4) |
        static_cast<uint16_t>(x[3]));
}

}  // namespace

uint16_t encrypt(uint16_t plaintext, uint32_t key) {
    const Subkeys k = generate_subkeys(key);
    auto x = split_block(plaintext);

    // Four complete rounds, each using six subkeys.
    for (int round = 0; round < 4; ++round) {
        encrypt_round(x, k, round * 6);
    }

    // Final half-round: multiply, add, add, multiply.
    x[0] = mul17(x[0], k[24]);
    x[1] = add16(x[1], k[25]);
    x[2] = add16(x[2], k[26]);
    x[3] = mul17(x[3], k[27]);

    return join_block(x);
}

uint16_t decrypt(uint16_t ciphertext, uint32_t key) {
    const Subkeys k = generate_subkeys(key);
    auto x = split_block(ciphertext);

    // Undo the final half-round.
    x[0] = mul17(x[0], inverse17(k[24]));
    x[1] = sub16(x[1], k[25]);
    x[2] = sub16(x[2], k[26]);
    x[3] = mul17(x[3], inverse17(k[27]));

    // Undo the complete rounds in reverse order.
    for (int round = 3; round >= 0; --round) {
        decrypt_round(x, k, round * 6);
    }

    return join_block(x);
}

}  // namespace simplified_idea

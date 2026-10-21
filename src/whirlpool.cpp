// Author: Vem Nagarjuna Reddy
// Roll Number: 20243315
// Purpose: Whirlpool (current 2003/ISO variant) hash implementation.

#include "whirlpool.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

namespace crypto {
namespace {

constexpr array<uint8_t, 256> SBOX = {{0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52, 0x60, 0xBC, 0x9B, 0x8E, 0xA3, 0x0C, 0x7B, 0x35, 0x1D, 0xE0, 0xD7, 0xC2, 0x2E, 0x4B, 0xFE, 0x57, 0x15, 0x77, 0x37, 0xE5, 0x9F, 0xF0, 0x4A, 0xDA, 0x58, 0xC9, 0x29, 0x0A, 0xB1, 0xA0, 0x6B, 0x85, 0xBD, 0x5D, 0x10, 0xF4, 0xCB, 0x3E, 0x05, 0x67, 0xE4, 0x27, 0x41, 0x8B, 0xA7, 0x7D, 0x95, 0xD8, 0xFB, 0xEE, 0x7C, 0x66, 0xDD, 0x17, 0x47, 0x9E, 0xCA, 0x2D, 0xBF, 0x07, 0xAD, 0x5A, 0x83, 0x33, 0x63, 0x02, 0xAA, 0x71, 0xC8, 0x19, 0x49, 0xD9, 0xF2, 0xE3, 0x5B, 0x88, 0x9A, 0x26, 0x32, 0xB0, 0xE9, 0x0F, 0xD5, 0x80, 0xBE, 0xCD, 0x34, 0x48, 0xFF, 0x7A, 0x90, 0x5F, 0x20, 0x68, 0x1A, 0xAE, 0xB4, 0x54, 0x93, 0x22, 0x64, 0xF1, 0x73, 0x12, 0x40, 0x08, 0xC3, 0xEC, 0xDB, 0xA1, 0x8D, 0x3D, 0x97, 0x00, 0xCF, 0x2B, 0x76, 0x82, 0xD6, 0x1B, 0xB5, 0xAF, 0x6A, 0x50, 0x45, 0xF3, 0x30, 0xEF, 0x3F, 0x55, 0xA2, 0xEA, 0x65, 0xBA, 0x2F, 0xC0, 0xDE, 0x1C, 0xFD, 0x4D, 0x92, 0x75, 0x06, 0x8A, 0xB2, 0xE6, 0x0E, 0x1F, 0x62, 0xD4, 0xA8, 0x96, 0xF9, 0xC5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4C, 0x5E, 0x78, 0x38, 0x8C, 0xD1, 0xA5, 0xE2, 0x61, 0xB3, 0x21, 0x9C, 0x1E, 0x43, 0xC7, 0xFC, 0x04, 0x51, 0x99, 0x6D, 0x0D, 0xFA, 0xDF, 0x7E, 0x24, 0x3B, 0xAB, 0xCE, 0x11, 0x8F, 0x4E, 0xB7, 0xEB, 0x3C, 0x81, 0x94, 0xF7, 0xB9, 0x13, 0x2C, 0xD3, 0xE7, 0x6E, 0xC4, 0x03, 0x56, 0x44, 0x7F, 0xA9, 0x2A, 0xBB, 0xC1, 0x53, 0xDC, 0x0B, 0x9D, 0x6C, 0x31, 0x74, 0xF6, 0x46, 0xAC, 0x89, 0x14, 0xE1, 0x16, 0x3A, 0x69, 0x09, 0x70, 0xB6, 0xD0, 0xED, 0xCC, 0x42, 0x98, 0xA4, 0x28, 0x5C, 0xF8, 0x86}};

constexpr array<uint64_t, 10> ROUND_CONSTANTS = {{0x1823C6E887B8014FULL, 0x36A6D2F5796F9152ULL, 0x60BC9B8EA30C7B35ULL, 0x1DE0D7C22E4BFE57ULL, 0x157737E59FF04ADAULL, 0x58C9290AB1A06B85ULL, 0xBD5D10F4CB3E0567ULL, 0xE427418BA77D95D8ULL, 0xFBEE7C66DD17479EULL, 0xCA2DBF07AD5A8333ULL}};

// Multiply two bytes in GF(2^8), using Whirlpool's polynomial x^8+x^4+x^3+x^2+1 (0x11D).
uint8_t gfMultiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        if ((b & 1U) != 0) result ^= a;
        const bool highBit = (a & 0x80U) != 0;
        a = static_cast<uint8_t>(a << 1U);
        if (highBit) a ^= 0x1DU;  // low byte of 0x11D
        b = static_cast<uint8_t>(b >> 1U);
    }
    return result;
}

constexpr uint64_t rotateRight64(uint64_t value, unsigned int bits) {
    return (value >> bits) | (value << (64U - bits));
}

using TableSet = array<array<uint64_t, 256>, 8>;

// Generate Whirlpool's eight 64-bit transformation tables from the S-box.
TableSet makeTables() {
    TableSet tables{};
    for (size_t i = 0; i < SBOX.size(); ++i) {
        const uint8_t x = SBOX[i];
        const uint8_t x2 = gfMultiply(x, 2);
        const uint8_t x4 = gfMultiply(x, 4);
        const uint8_t x5 = static_cast<uint8_t>(x4 ^ x);
        const uint8_t x8 = gfMultiply(x, 8);
        const uint8_t x9 = static_cast<uint8_t>(x8 ^ x);

        // Circulant diffusion row: (1, 1, 4, 1, 8, 5, 2, 9).
        const uint64_t t0 = (static_cast<uint64_t>(x) << 56U) |
                            (static_cast<uint64_t>(x) << 48U) |
                            (static_cast<uint64_t>(x4) << 40U) |
                            (static_cast<uint64_t>(x) << 32U) |
                            (static_cast<uint64_t>(x8) << 24U) |
                            (static_cast<uint64_t>(x5) << 16U) |
                            (static_cast<uint64_t>(x2) << 8U) |
                            static_cast<uint64_t>(x9);

        for (unsigned int r = 0; r < 8; ++r) {
            tables[r][i] = rotateRight64(t0, 8U * r);
        }
    }
    return tables;
}

const TableSet TABLES = makeTables();

uint64_t readBigEndian64(const uint8_t* bytes) {
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i) {
        value = (value << 8U) | bytes[i];
    }
    return value;
}

void writeBigEndian64(uint64_t value, uint8_t* bytes) {
    for (int i = 7; i >= 0; --i) {
        bytes[i] = static_cast<uint8_t>(value & 0xFFU);
        value >>= 8U;
    }
}

// Whirlpool's combined SubBytes, ShiftColumns and MixRows transform.
uint64_t transformWord(const array<uint64_t, 8>& input, size_t shift) {
    return TABLES[0][static_cast<uint8_t>(input[shift] >> 56U)] ^
           TABLES[1][static_cast<uint8_t>(input[(shift + 7U) & 7U] >> 48U)] ^
           TABLES[2][static_cast<uint8_t>(input[(shift + 6U) & 7U] >> 40U)] ^
           TABLES[3][static_cast<uint8_t>(input[(shift + 5U) & 7U] >> 32U)] ^
           TABLES[4][static_cast<uint8_t>(input[(shift + 4U) & 7U] >> 24U)] ^
           TABLES[5][static_cast<uint8_t>(input[(shift + 3U) & 7U] >> 16U)] ^
           TABLES[6][static_cast<uint8_t>(input[(shift + 2U) & 7U] >> 8U)] ^
           TABLES[7][static_cast<uint8_t>(input[(shift + 1U) & 7U])];
}

void processBlock(array<uint64_t, 8>& hash, const uint8_t* block) {
    array<uint64_t, 8> message{};
    array<uint64_t, 8> key = hash;
    array<uint64_t, 8> state{};

    for (size_t i = 0; i < 8; ++i) {
        message[i] = readBigEndian64(block + i * 8U);
        state[i] = message[i] ^ hash[i];
    }

    for (size_t round = 0; round < 10; ++round) {
        array<uint64_t, 8> nextKey{};
        array<uint64_t, 8> nextState{};

        for (size_t i = 0; i < 8; ++i) {
            nextKey[i] = transformWord(key, i);
        }
        nextKey[0] ^= ROUND_CONSTANTS[round];

        for (size_t i = 0; i < 8; ++i) {
            nextState[i] = transformWord(state, i) ^ nextKey[i];
        }

        key = nextKey;
        state = nextState;
    }

    // Miyaguchi–Preneel compression: H = H XOR message XOR cipher(H, message).
    for (size_t i = 0; i < 8; ++i) {
        hash[i] ^= message[i] ^ state[i];
    }
}

}  // namespace

WhirlpoolDigest whirlpool(const vector<uint8_t>& message) {
    // This interface uses byte-sized messages, so their bit length fits in
    // the low 64 bits for all realistically addressable input vectors.
    if (message.size() > (numeric_limits<uint64_t>::max() / 8U)) {
        throw length_error("Whirlpool input is too large");
    }

    const uint64_t bitLength = static_cast<uint64_t>(message.size()) * 8U;

    array<uint64_t, 8> hash{};  // Whirlpool IV is 512 zero bits.
    size_t offset = 0;

    while (message.size() - offset >= 64U) {
        processBlock(hash, message.data() + offset);
        offset += 64U;
    }

    // Whirlpool padding: append 1 bit, zeros, then the 256-bit big-endian
    // message length. With a byte-oriented API, append 0x80 after the data.
    array<uint8_t, 128> finalBlocks{};
    const size_t remaining = message.size() - offset;
    copy(message.begin() + static_cast<ptrdiff_t>(offset), message.end(), finalBlocks.begin());
    finalBlocks[remaining] = 0x80U;

    // The final 32 bytes hold the 256-bit length. For inputs representable
    // by this API, the upper 192 bits are zero and the low 64 bits are length.
    const size_t lengthPosition = (remaining + 1U <= 32U) ? 32U : 96U;
    writeBigEndian64(bitLength, finalBlocks.data() + lengthPosition + 24U);

    const size_t finalBytes = (lengthPosition == 32U) ? 64U : 128U;
    processBlock(hash, finalBlocks.data());
    if (finalBytes == 128U) {
        processBlock(hash, finalBlocks.data() + 64U);
    }

    WhirlpoolDigest digest{};
    for (size_t i = 0; i < 8; ++i) {
        writeBigEndian64(hash[i], digest.data() + i * 8U);
    }
    return digest;
}

string whirlpoolHex(const string& message) {
    const vector<uint8_t> bytes(message.begin(), message.end());
    const WhirlpoolDigest digest = whirlpool(bytes);

    ostringstream output;
    output << uppercase << hex << setfill('0');
    for (const uint8_t byte : digest) {
        output << setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

}  // namespace crypto

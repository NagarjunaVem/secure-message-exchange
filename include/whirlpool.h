// Author: Vem Nagarjuna Reddy
// Roll Number: 20243315
// Purpose: Whirlpool 512-bit hash interface.

#ifndef WHIRLPOOL_H
#define WHIRLPOOL_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {

using WhirlpoolDigest = std::array<std::uint8_t, 64>;

WhirlpoolDigest whirlpool(const std::vector<std::uint8_t>& message);

std::string whirlpoolHex(const std::string& message);

}  // namespace crypto

#endif
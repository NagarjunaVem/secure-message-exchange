/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 * Purpose: Serialize the client/server cryptographic exchange frames.
 */

#ifndef EXCHANGE_PROTOCOL_H
#define EXCHANGE_PROTOCOL_H

#include "secure_exchange.h"

#include <cstdint>
#include <string>
#include <vector>

namespace exchange_protocol {

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint8_t REQUEST_PUBLIC_KEY = 0x01;
constexpr std::uint8_t SERVER_PUBLIC_KEY = 0x02;
constexpr std::uint8_t CLIENT_CRYPTO_PACKET = 0x03;
constexpr std::uint8_t SERVER_RESULT = 0x04;

struct ServerReply {
    bool signatureValid = false;
    std::string message;
    crypto::WhirlpoolDigest digest{};
};

Bytes encodePublicKey(const elgamal::PublicKey& key);
elgamal::PublicKey decodePublicKey(const Bytes& frame);

Bytes encodeClientPacket(const secure_exchange::ClientPacket& packet);
secure_exchange::ClientPacket decodeClientPacket(const Bytes& frame);

Bytes encodeServerReply(const secure_exchange::ServerResult& result);
ServerReply decodeServerReply(const Bytes& frame);

}  // namespace exchange_protocol

#endif

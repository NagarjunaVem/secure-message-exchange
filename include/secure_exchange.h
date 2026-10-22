/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 * Purpose: In-memory client/server cryptographic exchange.
 */

#ifndef SECURE_EXCHANGE_H
#define SECURE_EXCHANGE_H

#include "elgamal.h"
#include "simplified_idea.h"
#include "whirlpool.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace secure_exchange {

    using ProgressCallback = std::function<void(const std::string&)>;

    struct ClientPacket {
        std::vector<std::uint16_t> ciphertextBlocks;
        std::size_t messageLength = 0;
        std::vector<elgamal::Ciphertext> encryptedSecretKey;
        elgamal::PublicKey clientPublicKey{};
        elgamal::Signature signature{};
        std::vector<simplified_idea::BlockTrace> encryptionTrace;
    };

    struct ServerResult {
        std::string message;
        std::uint32_t secretKey = 0;
        crypto::WhirlpoolDigest digest{};
        bool signatureValid = false;
        std::vector<simplified_idea::BlockTrace> decryptionTrace;
    };

    // Encrypts the message with IDEA, wraps its key for the server, and signs its
    // Whirlpool digest with the client's ElGamal private key.
    ClientPacket prepareClientPacket(const std::string& message, std::uint32_t secretKey, const elgamal::KeyPair& clientKeys, const elgamal::PublicKey& serverPublicKey, const ProgressCallback& progress = {});

    // Recovers the IDEA key and message, then verifies the client's signature.
    ServerResult processClientPacket(const ClientPacket& packet, const elgamal::KeyPair& serverKeys, const ProgressCallback& progress = {});

    std::string digestHex(const crypto::WhirlpoolDigest& digest);

}  // namespace secure_exchange

#endif

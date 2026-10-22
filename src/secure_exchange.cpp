/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 * Purpose: Connect IDEA, ElGamal, and Whirlpool for a secure message exchange.
 */

#include "secure_exchange.h"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <random>
#include <sstream>
#include <stdexcept>

using namespace std;

namespace secure_exchange {
namespace {

bool isPrime(elgamal::Number value) {
    if (value < 2) {
        return false;
    }
    if (value % 2 == 0) {
        return value == 2;
    }
    for (elgamal::Number divisor = 3; divisor <= value / divisor; divisor += 2) {
        if (value % divisor == 0) {
            return false;
        }
    }
    return true;
}

void validatePublicKey(const elgamal::PublicKey& key) {
    if (key.p > numeric_limits<uint32_t>::max() || !isPrime(key.p) || key.g < 2 || key.g >= key.p || key.y < 1 || key.y >= key.p) {
        throw invalid_argument("ElGamal needs a prime p no larger than 32 bits and valid g,y values");
    }

    elgamal::Number remainder = key.p - 1;
    for (elgamal::Number factor = 2; factor <= remainder / factor; ++factor) {
        if (remainder % factor != 0) {
            continue;
        }
        if (elgamal::modPow(key.g, (key.p - 1) / factor, key.p) == 1) {
            throw invalid_argument("ElGamal g must generate the nonzero values modulo p");
        }
        while (remainder % factor == 0) {
            remainder /= factor;
        }
    }
    if (remainder > 1 && elgamal::modPow(key.g, (key.p - 1) / remainder, key.p) == 1) {
        throw invalid_argument("ElGamal g must generate the nonzero values modulo p");
    }
}

void validateKeyPair(const elgamal::KeyPair& keys) {
    validatePublicKey(keys.publicKey);
    if (keys.privateKey < 1 || keys.privateKey >= keys.publicKey.p - 1 || elgamal::modPow(keys.publicKey.g, keys.privateKey, keys.publicKey.p) != keys.publicKey.y) {
        throw invalid_argument("ElGamal private and public key parameters do not match");
    }
}

elgamal::Number greatestCommonDivisor(elgamal::Number a, elgamal::Number b) {
    while (b != 0) {
        const elgamal::Number remainder = a % b;
        a = b;
        b = remainder;
    }
    return a;
}

elgamal::Number randomNonce(elgamal::Number p) {
    static random_device source;
    uniform_int_distribution<elgamal::Number> distribution(1, p - 2);
    return distribution(source);
}

elgamal::Number randomSignatureNonce(elgamal::Number p) {
    // A signature nonce must have an inverse modulo p-1.
    elgamal::Number candidate = randomNonce(p);
    while (greatestCommonDivisor(candidate, p - 1) != 1) {
        candidate = randomNonce(p);
    }
    return candidate;
}

vector<elgamal::Number> splitSecretKey(uint32_t secretKey, elgamal::Number base) {
    vector<elgamal::Number> digits;
    elgamal::Number remaining = secretKey;
    do {
        digits.push_back(remaining % base);
        remaining /= base;
    } while (remaining != 0);
    reverse(digits.begin(), digits.end());
    return digits;
}

elgamal::Number digestToScalar(const crypto::WhirlpoolDigest& digest, elgamal::Number modulus) {
    // Fold all 512 digest bits into the scalar domain without truncating bytes.
    elgamal::Number value = 0;
    for (const uint8_t byte : digest) {
        value = (value * 256U + byte) % modulus;
    }
    return value;
}

crypto::WhirlpoolDigest hashMessage(const string& message) {
    vector<uint8_t> bytes;
    bytes.reserve(message.size());
    for (const unsigned char byte : message) {
        bytes.push_back(byte);
    }
    return crypto::whirlpool(bytes);
}

}  // namespace

ClientPacket prepareClientPacket(const string& message, uint32_t secretKey, const elgamal::KeyPair& clientKeys, const elgamal::PublicKey& serverPublicKey, const ProgressCallback& progress) {
    validateKeyPair(clientKeys);
    validatePublicKey(serverPublicKey);

    ClientPacket packet;
    packet.messageLength = message.size();
    packet.clientPublicKey = clientKeys.publicKey;

    // Encrypt each two-byte part of the message with IDEA.
    // Save the original length so padding can be removed after decryption.
    if (progress) progress("IDEA: encrypting the message in 16-bit blocks with the client key.");
    for (size_t offset = 0; offset < message.size(); offset += 2) {
        const auto high = static_cast<uint8_t>(message[offset]);
        const auto low = (offset + 1 < message.size())
                             ? static_cast<uint8_t>(message[offset + 1])
                             : 0U;
        const uint16_t plaintext = static_cast<uint16_t>((static_cast<uint16_t>(high) << 8U) | low);
        simplified_idea::BlockTrace trace;
        packet.ciphertextBlocks.push_back(simplified_idea::encrypt(plaintext, secretKey, &trace));
        packet.encryptionTrace.push_back(trace);
    }

    // Split the IDEA key into base-p digits because ElGamal handles small integers.
    if (progress) progress("ElGamal: encrypting the IDEA key digits with the server public key.");
    for (const elgamal::Number digit : splitSecretKey(secretKey, serverPublicKey.p)) {
        packet.encryptedSecretKey.push_back(elgamal::encrypt(digit, serverPublicKey, randomNonce(serverPublicKey.p)));
    }

    // Hash the original message and sign the hash with the client's private key.
    if (progress) progress("Whirlpool: calculating the message hash.");
    const crypto::WhirlpoolDigest digest = hashMessage(message);
    const elgamal::Number signingValue = digestToScalar(digest, clientKeys.publicKey.p - 1);
    if (progress) progress("ElGamal: signing the Whirlpool hash with the client private key.");
    packet.signature = elgamal::sign(signingValue, clientKeys, randomSignatureNonce(clientKeys.publicKey.p));
    return packet;
}

ServerResult processClientPacket(const ClientPacket& packet, const elgamal::KeyPair& serverKeys, const ProgressCallback& progress) {
    validateKeyPair(serverKeys);
    validatePublicKey(packet.clientPublicKey);

    const size_t expectedBlocks = packet.messageLength / 2U + packet.messageLength % 2U;
    if (packet.ciphertextBlocks.size() != expectedBlocks || packet.encryptedSecretKey.empty()) {
        throw invalid_argument("Malformed encrypted message packet");
    }

    // Decrypt each key digit and join the digits back into the IDEA key.
    if (progress) progress("ElGamal: decrypting the wrapped IDEA key with the server private key.");
    elgamal::Number recoveredKey = 0;
    for (const elgamal::Ciphertext& encryptedDigit : packet.encryptedSecretKey) {
        const elgamal::Number digit = elgamal::decrypt(encryptedDigit, serverKeys);
        if (digit >= serverKeys.publicKey.p || recoveredKey > (numeric_limits<uint32_t>::max() - digit) / serverKeys.publicKey.p) {
            throw invalid_argument("Encrypted IDEA key is out of range");
        }
        recoveredKey = recoveredKey * serverKeys.publicKey.p + digit;
    }

    ServerResult result;
    result.secretKey = static_cast<uint32_t>(recoveredKey);
    result.message.reserve(packet.ciphertextBlocks.size() * 2U);
    if (progress) progress("IDEA: decrypting the received message blocks with the recovered key.");
    for (const uint16_t ciphertext : packet.ciphertextBlocks) {
        simplified_idea::BlockTrace trace;
        const uint16_t plaintext = simplified_idea::decrypt(ciphertext, result.secretKey, &trace);
        result.decryptionTrace.push_back(trace);
        result.message.push_back(static_cast<char>(plaintext >> 8U));
        result.message.push_back(static_cast<char>(plaintext & 0xFFU));
    }
    result.message.resize(packet.messageLength);

    // Hash the recovered message and check the client's signature.
    if (progress) progress("Whirlpool: calculating a fresh hash of the recovered message.");
    result.digest = hashMessage(result.message);
    const elgamal::Number signingValue = digestToScalar(result.digest, packet.clientPublicKey.p - 1);
    if (progress) progress("ElGamal: verifying the signature with the client public key.");
    result.signatureValid = elgamal::verify(signingValue, packet.signature, packet.clientPublicKey);
    return result;
}

string digestHex(const crypto::WhirlpoolDigest& digest) {
    ostringstream output;
    output << uppercase << hex << setfill('0');
    for (const uint8_t byte : digest) {
        output << setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

}  // namespace secure_exchange

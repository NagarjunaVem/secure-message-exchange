/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 * Purpose: Encode and validate length-delimited exchange payloads.
 */

#include "exchange_protocol.h"

#include <limits>
#include <stdexcept>

using namespace std;

namespace exchange_protocol {
namespace {

void appendU8(Bytes& bytes, uint8_t value) {
    bytes.push_back(value);
}

void appendU16(Bytes& bytes, uint16_t value) {
    // Store numbers in network byte order: most significant byte first.
    bytes.push_back(static_cast<uint8_t>(value >> 8U));
    bytes.push_back(static_cast<uint8_t>(value));
}

void appendU32(Bytes& bytes, uint32_t value) {
    bytes.push_back(static_cast<uint8_t>(value >> 24U));
    bytes.push_back(static_cast<uint8_t>(value >> 16U));
    bytes.push_back(static_cast<uint8_t>(value >> 8U));
    bytes.push_back(static_cast<uint8_t>(value));
}

void appendU64(Bytes& bytes, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes.push_back(static_cast<uint8_t>(value >> shift));
    }
}

void appendText(Bytes& bytes, const string& text) {
    for (const unsigned char byte : text) {
        bytes.push_back(byte);
    }
}

class Reader {
   public:
    explicit Reader(const Bytes& bytes) : bytes_(bytes) {}

    uint8_t readU8() {
        require(1);
        return bytes_[offset_++];
    }

    uint16_t readU16() {
        const uint16_t high = readU8();
        return static_cast<uint16_t>((high << 8U) | readU8());
    }

    uint32_t readU32() {
        uint32_t value = 0;
        for (int i = 0; i < 4; ++i) {
            value = (value << 8U) | readU8();
        }
        return value;
    }

    uint64_t readU64() {
        uint64_t value = 0;
        for (int i = 0; i < 8; ++i) {
            value = (value << 8U) | readU8();
        }
        return value;
    }

    string readText(size_t size) {
        require(size);
        string value;
        value.resize(size);
        for (size_t i = 0; i < size; ++i) {
            value[i] = static_cast<char>(bytes_[offset_ + i]);
        }
        offset_ += size;
        return value;
    }

    crypto::WhirlpoolDigest readDigest() {
        require(crypto::WhirlpoolDigest{}.size());
        crypto::WhirlpoolDigest digest{};
        for (uint8_t& byte : digest) {
            byte = bytes_[offset_++];
        }
        return digest;
    }

    size_t remaining() const {
        return bytes_.size() - offset_;
    }

    void requireComplete() const {
        if (offset_ != bytes_.size()) {
            throw invalid_argument("Unexpected trailing bytes in exchange frame");
        }
    }

   private:
    void require(size_t count) const {
        if (count > bytes_.size() - offset_) {
            throw invalid_argument("Truncated exchange frame");
        }
    }

    const Bytes& bytes_;
    size_t offset_ = 0;
};

void expectType(Reader& reader, uint8_t expected) {
    if (reader.readU8() != expected) {
        throw invalid_argument("Unexpected exchange frame type");
    }
}

uint32_t checkedCount(size_t count, const char* field) {
    if (count > numeric_limits<uint32_t>::max()) {
        throw length_error(string(field) + " count exceeds the wire format");
    }
    return static_cast<uint32_t>(count);
}

}  // namespace

Bytes encodePublicKey(const elgamal::PublicKey& key) {
    Bytes frame;
    frame.reserve(25);
    appendU8(frame, SERVER_PUBLIC_KEY);
    appendU64(frame, key.p);
    appendU64(frame, key.g);
    appendU64(frame, key.y);
    return frame;
}

elgamal::PublicKey decodePublicKey(const Bytes& frame) {
    Reader reader(frame);
    expectType(reader, SERVER_PUBLIC_KEY);
    elgamal::PublicKey key{reader.readU64(), reader.readU64(), reader.readU64()};
    reader.requireComplete();
    return key;
}

Bytes encodeClientPacket(const secure_exchange::ClientPacket& packet) {
    // Keep each field in a fixed order so the server can read it back safely.
    Bytes frame;
    frame.reserve(1U + 8U + 4U + packet.ciphertextBlocks.size() * 2U + 4U + packet.encryptedSecretKey.size() * 16U + 40U);
    appendU8(frame, CLIENT_CRYPTO_PACKET);
    appendU64(frame, static_cast<uint64_t>(packet.messageLength));
    appendU32(frame, checkedCount(packet.ciphertextBlocks.size(), "Block"));
    for (const uint16_t block : packet.ciphertextBlocks) {
        appendU16(frame, block);
    }
    appendU32(frame, checkedCount(packet.encryptedSecretKey.size(), "Key digit"));
    for (const elgamal::Ciphertext& digit : packet.encryptedSecretKey) {
        appendU64(frame, digit.c1);
        appendU64(frame, digit.c2);
    }
    appendU64(frame, packet.clientPublicKey.p);
    appendU64(frame, packet.clientPublicKey.g);
    appendU64(frame, packet.clientPublicKey.y);
    appendU64(frame, packet.signature.r);
    appendU64(frame, packet.signature.s);
    return frame;
}

secure_exchange::ClientPacket decodeClientPacket(const Bytes& frame) {
    // Read the fields in the same order used by encodeClientPacket().
    Reader reader(frame);
    expectType(reader, CLIENT_CRYPTO_PACKET);
    const uint64_t messageLength = reader.readU64();
    if (messageLength > numeric_limits<size_t>::max()) {
        throw length_error("Message length is too large for this platform");
    }

    secure_exchange::ClientPacket packet;
    packet.messageLength = static_cast<size_t>(messageLength);
    const uint32_t blockCount = reader.readU32();
    const size_t expectedBlocks = packet.messageLength / 2U + packet.messageLength % 2U;
    if (blockCount != expectedBlocks || blockCount > reader.remaining() / 2U) {
        throw invalid_argument("Invalid IDEA ciphertext block count");
    }
    packet.ciphertextBlocks.reserve(blockCount);
    for (uint32_t i = 0; i < blockCount; ++i) {
        packet.ciphertextBlocks.push_back(reader.readU16());
    }

    const uint32_t keyDigitCount = reader.readU32();
    if (keyDigitCount == 0 || keyDigitCount > reader.remaining() / 16U) {
        throw invalid_argument("Invalid encrypted IDEA key digit count");
    }
    packet.encryptedSecretKey.reserve(keyDigitCount);
    for (uint32_t i = 0; i < keyDigitCount; ++i) {
        packet.encryptedSecretKey.push_back({reader.readU64(), reader.readU64()});
    }
    packet.clientPublicKey = {reader.readU64(), reader.readU64(), reader.readU64()};
    packet.signature = {reader.readU64(), reader.readU64()};
    reader.requireComplete();
    return packet;
}

Bytes encodeServerReply(const secure_exchange::ServerResult& result) {
    Bytes frame;
    frame.reserve(1U + 1U + 8U + result.message.size() + result.digest.size());
    appendU8(frame, SERVER_RESULT);
    appendU8(frame, result.signatureValid ? 1U : 0U);
    appendU64(frame, static_cast<uint64_t>(result.message.size()));
    appendText(frame, result.message);
    frame.insert(frame.end(), result.digest.begin(), result.digest.end());
    return frame;
}

ServerReply decodeServerReply(const Bytes& frame) {
    Reader reader(frame);
    expectType(reader, SERVER_RESULT);
    const uint8_t status = reader.readU8();
    if (status > 1U) {
        throw invalid_argument("Invalid server verification status");
    }
    const uint64_t messageLength = reader.readU64();
    const size_t digestLength = crypto::WhirlpoolDigest{}.size();
    if (reader.remaining() < digestLength || messageLength > numeric_limits<size_t>::max() || messageLength > reader.remaining() - digestLength) {
        throw invalid_argument("Invalid message length in server reply");
    }

    ServerReply reply;
    reply.signatureValid = status == 1U;
    reply.message = reader.readText(static_cast<size_t>(messageLength));
    reply.digest = reader.readDigest();
    reader.requireComplete();
    return reply;
}

}  // namespace exchange_protocol

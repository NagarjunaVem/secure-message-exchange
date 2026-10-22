/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 * Purpose: Send an IDEA-encrypted message with an ElGamal signature.
 */

#include "exchange_protocol.h"
#include "socket_utils.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

using namespace std;

namespace {

elgamal::KeyPair readClientKeys() {
    elgamal::Number p = 0;
    elgamal::Number g = 0;
    elgamal::Number x = 0;
    cout << "Client ElGamal parameters:\n";
    cout << "  Prime p (example: 467): ";
    cin >> p;
    cout << "  Generator g (example: 2): ";
    cin >> g;
    cout << "  Private key x (example: 127): ";
    cin >> x;
    if (!cin) {
        throw invalid_argument("Could not read client ElGamal parameters");
    }
    return elgamal::makeKeyPair(p, g, x);
}

void printKeyPair(const string& label, const elgamal::KeyPair& keys) {
    cout << label << " Public Key parameters (p, g, y): " << keys.publicKey.p << ", " << keys.publicKey.g << ", " << keys.publicKey.y << '\n';
    cout << label << " Private Key parameters (x): " << keys.privateKey << '\n';
}

void printNibbleState(const array<uint8_t, 4>& state) {
    for (const uint8_t nibble : state) {
        cout << hex << uppercase << static_cast<unsigned int>(nibble);
    }
    cout << dec;
}

void printEncryptionTrace(const vector<simplified_idea::BlockTrace>& traces) {
    cout << "Intermediate encryption process (14 steps per IDEA round):\n";
    for (size_t block = 0; block < traces.size(); ++block) {
        cout << "  Block " << block + 1 << ": ";
        for (size_t round = 0; round < 4; ++round) {
            cout << "R" << round + 1 << '[';
            for (size_t step = 0; step < 14; ++step) {
                cout << "S" << step + 1 << '=' << hex << uppercase << static_cast<unsigned int>(traces[block].roundSteps[round][step]);
                if (step != 13) {
                    cout << ',';
                }
            }
            cout << dec << "] ";
        }
        cout << "Final=";
        printNibbleState(traces[block].finalOutput);
        cout << '\n';
    }
    if (traces.empty()) {
        cout << "  (empty message; no IDEA blocks)\n";
    }
}

void printCiphertext(const vector<uint16_t>& blocks) {
    cout << hex << uppercase << setfill('0');
    for (size_t i = 0; i < blocks.size(); ++i) {
        if (i != 0) {
            cout << ' ';
        }
        cout << setw(4) << blocks[i];
    }
    cout << dec << setfill(' ');
    if (blocks.empty()) {
        cout << "(empty)";
    }
    cout << '\n';
}

uint16_t parsePort(const char* value) {
    const unsigned long parsed = stoul(value);
    if (parsed == 0 || parsed > numeric_limits<uint16_t>::max()) {
        throw invalid_argument("Port must be between 1 and 65535");
    }
    return static_cast<uint16_t>(parsed);
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc > 3) {
            throw invalid_argument("Usage: client [server-host] [port]");
        }
        const string host = (argc > 1) ? argv[1] : "127.0.0.1";
        const uint16_t port = (argc > 2) ? parsePort(argv[2]) : 8080;

        cout << "Secure Message Exchange - Client\n"
             << "Author: Vem Nagarjuna Reddy\n"
             << "Roll Number: 20243315\n\n";

        string message;
        cout << "Input message: ";
        getline(cin, message);

        uint32_t secretKey = 0;
        cout << "Secret Key (32-bit decimal, 0 to " << numeric_limits<uint32_t>::max() << "): ";
        cin >> secretKey;
        if (!cin) {
            throw invalid_argument("Could not read the 32-bit IDEA key");
        }
        const elgamal::KeyPair clientKeys = readClientKeys();
        cout << "Client key pair created; the public key will be shared and the private key is used for signing.\n";

        socket_utils::SocketRuntime runtime;
        cout << "Step 1: Connecting to server at " << host << ':' << port << ".\n";
        socket_utils::TcpSocket connection = socket_utils::TcpSocket::connectTo(host, port);

        // Get the server key before encrypting the IDEA key for the server.
        cout << "Step 2: Requesting the server public key over TCP; the public key is shared openly.\n";
        const uint8_t request = exchange_protocol::REQUEST_PUBLIC_KEY;
        socket_utils::sendFrame(connection, &request, 1);
        const vector<uint8_t> serverKeyFrame = socket_utils::receiveFrame(connection);
        const elgamal::PublicKey serverPublicKey = exchange_protocol::decodePublicKey(serverKeyFrame);
        cout << "Step 3: Received server public key (p, g, y): " << serverPublicKey.p << ", " << serverPublicKey.g << ", " << serverPublicKey.y << ".\n";

        cout << "Step 4: Preparing the protected message.\n";
        const secure_exchange::ClientPacket packet = secure_exchange::prepareClientPacket(message, secretKey, clientKeys, serverPublicKey, [](const string& step) { cout << "    -> " << step << '\n'; });

        cout << "\nClient Side:\n";
        cout << "Input: Message: " << message << '\n';
        cout << "Secret Key: 0x" << hex << uppercase << setw(8) << setfill('0') << secretKey << dec << setfill(' ') << " (32-bit)\n";
        printKeyPair("Client", clientKeys);
        cout << "Received Server Public Key parameters (p, g, y): " << serverPublicKey.p << ", " << serverPublicKey.g << ", " << serverPublicKey.y << '\n';
        printEncryptionTrace(packet.encryptionTrace);
        cout << "Cipher text (16-bit blocks, hex): ";
        printCiphertext(packet.ciphertextBlocks);
        cout << "Encrypted Secret Key (base-p digit ciphertexts): ";
        for (size_t i = 0; i < packet.encryptedSecretKey.size(); ++i) {
            if (i != 0) {
                cout << " | ";
            }
            cout << '(' << packet.encryptedSecretKey[i].c1 << ", " << packet.encryptedSecretKey[i].c2 << ')';
        }
        cout << '\n';
        const vector<uint8_t> messageBytes(message.begin(), message.end());
        const crypto::WhirlpoolDigest digest = crypto::whirlpool(messageBytes);
        cout << "Hash code (Whirlpool-512): " << secure_exchange::digestHex(digest) << '\n';
        cout << "Digital Signature (r, s): (" << packet.signature.r << ", " << packet.signature.s << ")\n";

        // Send the encrypted message, encrypted IDEA key, client key, and signature.
        cout << "Step 5: Sending ciphertext, wrapped key, client public key, and signature to server.\n";
        const vector<uint8_t> packetFrame = exchange_protocol::encodeClientPacket(packet);
        socket_utils::sendFrame(connection, packetFrame.data(), packetFrame.size());

        cout << "Step 6: Waiting for the server to decrypt and verify the message.\n";
        const exchange_protocol::ServerReply reply = exchange_protocol::decodeServerReply(socket_utils::receiveFrame(connection));
        cout << "Step 7: Server returned the verification result.\n";
        cout << "Server verification: " << (reply.signatureValid ? "valid" : "invalid") << '\n';
        cout << "Server message status: " << (reply.signatureValid ? "Accepted" : "Rejected") << '\n';
        cout << "Server hash code: " << secure_exchange::digestHex(reply.digest) << '\n';
        return reply.signatureValid ? 0 : 1;
    } catch (const exception& error) {
        cerr << "Client error: " << error.what() << '\n';
        return 1;
    }
}

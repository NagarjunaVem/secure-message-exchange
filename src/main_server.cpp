/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 * Purpose: Receive, decrypt, and verify a client's secure message.
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

elgamal::KeyPair readServerKeys() {
    elgamal::Number p = 0;
    elgamal::Number g = 0;
    elgamal::Number x = 0;
    cout << "Server ElGamal parameters:\n";
    cout << "  Prime p (example: 467): ";
    cin >> p;
    cout << "  Generator g (example: 2): ";
    cin >> g;
    cout << "  Private key x (example: 127): ";
    cin >> x;
    if (!cin) {
        throw invalid_argument("Could not read server ElGamal parameters");
    }
    return elgamal::makeKeyPair(p, g, x);
}

uint16_t parsePort(const char* value) {
    const unsigned long parsed = stoul(value);
    if (parsed == 0 || parsed > numeric_limits<uint16_t>::max()) {
        throw invalid_argument("Port must be between 1 and 65535");
    }
    return static_cast<uint16_t>(parsed);
}

void printNibbleState(const array<uint8_t, 4>& state) {
    for (const uint8_t nibble : state) {
        cout << hex << uppercase << static_cast<unsigned int>(nibble);
    }
    cout << dec;
}

void printDecryptionTrace(const vector<simplified_idea::BlockTrace>& traces) {
    cout << "Intermediate decryption process (inverse rounds 4 to 1):\n";
    for (size_t block = 0; block < traces.size(); ++block) {
        cout << "  Block " << block + 1 << ": ";
        for (size_t round = 0; round < 4; ++round) {
            cout << "undo-R" << 4U - round << '=';
            printNibbleState(traces[block].roundOutput[round]);
            cout << ' ';
        }
        cout << "Recovered=";
        printNibbleState(traces[block].finalOutput);
        cout << '\n';
    }
    if (traces.empty()) {
        cout << "  (empty message; no IDEA blocks)\n";
    }
}

void printServerResult(const secure_exchange::ClientPacket& packet, const secure_exchange::ServerResult& result, const elgamal::KeyPair& serverKeys) {
    cout << "\nServer Side:\n";
    cout << "Input: Public Key parameters (p, g, y): " << serverKeys.publicKey.p << ", " << serverKeys.publicKey.g << ", " << serverKeys.publicKey.y << '\n';
    cout << "Private key parameters (x): " << serverKeys.privateKey << '\n';
    cout << "Client Public Key parameters (p, g, y): " << packet.clientPublicKey.p << ", " << packet.clientPublicKey.g << ", " << packet.clientPublicKey.y << '\n';
    cout << "Decrypted Secret Key: 0x" << hex << uppercase << setw(8) << setfill('0') << result.secretKey << dec << setfill(' ') << " (32-bit)\n";
    printDecryptionTrace(result.decryptionTrace);
    cout << "Decrypt Message: " << result.message << '\n';
    cout << "Hash code (Whirlpool-512): " << secure_exchange::digestHex(result.digest) << '\n';
    cout << "Verification code: " << (result.signatureValid ? "valid" : "invalid") << '\n';
    cout << "Signature: " << (result.signatureValid ? "valid" : "invalid") << '\n';
    cout << "Message: " << (result.signatureValid ? "Accepted" : "Rejected") << '\n';
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc > 2) {
            throw invalid_argument("Usage: server [port]");
        }
        const uint16_t port = (argc > 1) ? parsePort(argv[1]) : 8080;
        cout << "Secure Message Exchange - Server\n" << "Author: Vem Nagarjuna Reddy\n" << "Roll Number: 20243315\n\n";
        const elgamal::KeyPair serverKeys = readServerKeys();

        socket_utils::SocketRuntime runtime;
        socket_utils::TcpSocket listener = socket_utils::TcpSocket::listenOn(port);
        cout << "Step 1: Listening on port " << port << "; waiting for a client...\n";
        socket_utils::TcpSocket connection = listener.acceptOne();
        cout << "Step 2: Client connected.\n";

        // The client first requests the server's public key.
        cout << "Step 3: Waiting for the client to request the server public key.\n";
        const vector<uint8_t> request = socket_utils::receiveFrame(connection, 1);
        if (request.size() != 1 || request[0] != exchange_protocol::REQUEST_PUBLIC_KEY) {
            throw invalid_argument("Expected a server public-key request");
        }

        const vector<uint8_t> publicKeyFrame = exchange_protocol::encodePublicKey(serverKeys.publicKey);
        socket_utils::sendFrame(connection, publicKeyFrame.data(), publicKeyFrame.size());
        cout << "Step 4: Sent server public key over TCP (p, g, y): " << serverKeys.publicKey.p << ", " << serverKeys.publicKey.g << ", " << serverKeys.publicKey.y << ".\n";

        // Receive the encrypted message packet and run the server-side steps.
        cout << "Step 5: Waiting for the encrypted message packet and signature.\n";
        const vector<uint8_t> packetFrame = socket_utils::receiveFrame(connection);
        const secure_exchange::ClientPacket packet = exchange_protocol::decodeClientPacket(packetFrame);
        cout << "Step 6: Received packet; client public key (p, g, y): " << packet.clientPublicKey.p << ", " << packet.clientPublicKey.g << ", " << packet.clientPublicKey.y << ".\n";
        cout << "Step 7: Processing the received packet.\n";
        const secure_exchange::ServerResult result = secure_exchange::processClientPacket(packet, serverKeys, [](const string& step) { cout << "    -> " << step << '\n'; });
        printServerResult(packet, result, serverKeys);

        const vector<uint8_t> reply = exchange_protocol::encodeServerReply(result);
        socket_utils::sendFrame(connection, reply.data(), reply.size());
        cout << "Step 8: Sent signature verification result to the client.\n";
        return result.signatureValid ? 0 : 1;
    } catch (const exception& error) {
        cerr << "Server error: " << error.what() << '\n';
        return 1;
    }
}

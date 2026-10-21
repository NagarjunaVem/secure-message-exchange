/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 * Purpose: Demonstrate message encryption, hashing, signing, and verification.
 */

#include "secure_exchange.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

using namespace std;

namespace {

elgamal::KeyPair readKeyPair(const string& label) {
    elgamal::Number p = 0;
    elgamal::Number g = 0;
    elgamal::Number x = 0;

    cout << label << " ElGamal parameters (educational values):\n";
    cout << "  Enter prime p (example: 467): ";
    cin >> p;
    cout << "  Enter generator g (example: 2): ";
    cin >> g;
    cout << "  Enter private key x (example: 127): ";
    cin >> x;
    if (!cin) {
        throw invalid_argument("Could not read ElGamal parameters");
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

void printIdeaTrace(const string& label, const vector<simplified_idea::BlockTrace>& traces, bool decryption = false) {
    if (decryption) {
        cout << label << " (inverse rounds 4 to 1, then recovered block):\n";
    } else {
        cout << label << " (the 14 intermediate steps of each round, then final transform):\n";
    }
    for (size_t block = 0; block < traces.size(); ++block) {
        cout << "  Block " << block + 1 << ": ";
        for (size_t round = 0; round < 4; ++round) {
            if (decryption) {
                cout << "undo-R" << 4U - round << '=';
                printNibbleState(traces[block].roundOutput[round]);
                cout << ' ';
            } else {
                cout << "R" << round + 1 << '[';
                for (size_t step = 0; step < 14; ++step) {
                    cout << "S" << step + 1 << '=' << hex << uppercase << static_cast<unsigned int>(traces[block].roundSteps[round][step]);
                    if (step != 13) {
                        cout << ',';
                    }
                }
                cout << dec << "] ";
            }
        }
        cout << "Final=";
        printNibbleState(traces[block].finalOutput);
        cout << '\n';
    }
    if (traces.empty()) {
        cout << "  (empty message; no IDEA blocks)\n";
    }
}

void printHexBlocks(const vector<uint16_t>& blocks) {
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
}

void printEncryptedKey(const vector<elgamal::Ciphertext>& encryptedKey) {
    cout << "Encrypted Secret Key (base-p digit ciphertexts): ";
    for (size_t i = 0; i < encryptedKey.size(); ++i) {
        if (i != 0) {
            cout << " | ";
        }
        cout << '(' << encryptedKey[i].c1 << ", " << encryptedKey[i].c2 << ')';
    }
    cout << '\n';
}

}  // namespace

int main() {
    try {
        cout << "Secure Message Exchange - Cryptography Demo\n" << "Author: Vem Nagarjuna Reddy\n" << "Roll Number: 20243315\n\n";

        string message;
        cout << "Client input message: ";
        getline(cin, message);

        uint32_t secretKey = 0;
        cout << "Client input Simplified IDEA secret key (decimal, 0 to " << numeric_limits<uint32_t>::max() << "): ";
        cin >> secretKey;
        if (!cin) {
            throw invalid_argument("Could not read the 32-bit IDEA key");
        }

        const elgamal::KeyPair clientKeys = readKeyPair("Client");
        const elgamal::KeyPair serverKeys = readKeyPair("Server");

        cout << "\nClient Side:\n";
        cout << "Input: Message: " << message << '\n';
        cout << "Secret Key: 0x" << hex << uppercase << setw(8) << setfill('0') << secretKey << dec << setfill(' ') << " (32-bit)\n";
        printKeyPair("Client", clientKeys);

        const secure_exchange::ClientPacket packet = secure_exchange::prepareClientPacket(message, secretKey, clientKeys, serverKeys.publicKey);
        printIdeaTrace("Intermediate encryption process", packet.encryptionTrace);
        cout << "Cipher text (16-bit blocks, hex): ";
        printHexBlocks(packet.ciphertextBlocks);
        cout << '\n';
        printEncryptedKey(packet.encryptedSecretKey);

        // Print the same full Whirlpool digest that is converted to the
        // ElGamal scalar by reducing all 512 bits modulo p-1.
        const auto clientDigest = crypto::whirlpool(vector<uint8_t>(message.begin(), message.end()));
        cout << "Hash code (Whirlpool-512): " << secure_exchange::digestHex(clientDigest) << '\n';
        cout << "Digital Signature (r, s): (" << packet.signature.r << ", " << packet.signature.s << ")\n";

        cout << "\nServer Side:\n";
        printKeyPair("Server", serverKeys);
        cout << "Client Public Key parameters (p, g, y): " << packet.clientPublicKey.p << ", " << packet.clientPublicKey.g << ", " << packet.clientPublicKey.y << '\n';

        const secure_exchange::ServerResult result = secure_exchange::processClientPacket(packet, serverKeys);
        cout << "Decrypted Secret Key: 0x" << hex << uppercase << setw(8) << setfill('0') << result.secretKey << dec << setfill(' ') << " (32-bit)\n";
        printIdeaTrace("Intermediate decryption process", result.decryptionTrace, true);
        cout << "Decrypt Message: " << result.message << '\n';
        cout << "Hash code (Whirlpool-512): " << secure_exchange::digestHex(result.digest) << '\n';
        cout << "Verification code: " << (result.signatureValid ? "valid" : "invalid") << '\n';
        cout << "Signature: " << (result.signatureValid ? "valid" : "invalid") << '\n';
        cout << "Message: " << (result.signatureValid ? "Accepted" : "Rejected") << '\n';
        return result.signatureValid ? 0 : 1;
    } catch (const exception& error) {
        cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}

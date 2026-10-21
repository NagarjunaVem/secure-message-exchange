// Author: Vem Nagarjuna Reddy
// Roll Number: 20243315
// Purpose: ElGamal key, encryption, and signature declarations.

#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <cstdint>

namespace elgamal {

using Number = std::uint64_t;

struct PublicKey {
    Number p;
    Number g;
    Number y;
};

struct KeyPair {
    PublicKey publicKey;
    Number privateKey;
};

struct Ciphertext {
    Number c1;
    Number c2;
};

// Calculate (base^exponent) mod modulus.
Number modPow(Number base, Number exponent, Number modulus);

// Generate an ElGamal key pair using p, g and private key x.
KeyPair makeKeyPair(Number p, Number g, Number x);

// Encrypt an integer message using a fresh ephemeral key k.
Ciphertext encrypt(Number message, const PublicKey& key, Number k);

// Decrypt an ElGamal ciphertext.
Number decrypt(const Ciphertext& ciphertext, const KeyPair& key);

struct Signature {
    Number r;
    Number s;
};

// Sign a message hash using the private key x.
// The nonce k must be fresh, secret, and coprime to p - 1.
Signature sign(Number hash, const KeyPair& keys, Number k);

// Verify a signature using the public key.
bool verify(Number hash, const Signature& signature, const PublicKey& key);

}  // namespace elgamal

#endif

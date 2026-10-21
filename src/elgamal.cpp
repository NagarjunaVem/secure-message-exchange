// Author: Vem Nagarjuna Reddy
// Roll Number: 20243315
// Purpose: ElGamal encryption, decryption, and digital signatures.

#include "elgamal.h"

#include <cstdint>
#include <stdexcept>

using namespace std;

namespace elgamal {

Number modPow(Number base, Number exponent, Number modulus) {
    if (modulus < 2) {
        throw invalid_argument("Modulus must be at least 2");
    }

    // Repeated squaring calculates the power without a large intermediate value.
    Number result = 1;
    base %= modulus;

    while (exponent > 0) {
        if (exponent & 1U) {
            result = (result * base) % modulus;
        }

        base = (base * base) % modulus;
        exponent >>= 1U;
    }

    return result;
}

KeyPair makeKeyPair(Number p, Number g, Number x) {
    if (p < 5 || g < 2 || g >= p || x < 1 || x >= p - 1) {
        throw invalid_argument("Invalid ElGamal parameters");
    }

    KeyPair keys;
    keys.publicKey = {p, g, modPow(g, x, p)};
    keys.privateKey = x;

    return keys;
}

Ciphertext encrypt(Number message, const PublicKey& key, Number k) {
    if (key.p < 5 || key.g < 2 || key.g >= key.p || key.y < 1 || key.y >= key.p || message >= key.p || k < 1 || k >= key.p - 1) {
        throw invalid_argument("Invalid encryption parameters");
    }

    // ElGamal encryption uses the receiver's public key and a fresh nonce.
    const Number c1 = modPow(key.g, k, key.p);
    const Number shared = modPow(key.y, k, key.p);
    const Number c2 = (message * shared) % key.p;

    return {c1, c2};
}

Number decrypt(const Ciphertext& ciphertext, const KeyPair& key) {
    const Number p = key.publicKey.p;

    if (p < 5 || ciphertext.c1 < 1 || ciphertext.c1 >= p || ciphertext.c2 >= p) {
        throw invalid_argument("Invalid ciphertext");
    }

    // The private key recreates the shared value used by the sender.
    const Number shared = modPow(ciphertext.c1, key.privateKey, p);

    // Find the multiplicative inverse of shared modulo p.
    // This implementation assumes p is prime.
    const Number inverse = modPow(shared, p - 2, p);

    return (ciphertext.c2 * inverse) % p;
}

namespace {

Number gcd(Number a, Number b) {
    while (b != 0) {
        Number remainder = a % b;
        a = b;
        b = remainder;
    }
    return a;
}

Number modInverse(Number a, Number modulus) {
    // Extended Euclidean algorithm.
    // Signed arithmetic is used for the coefficients.
    int64_t t = 0, newT = 1;
    int64_t r = static_cast<int64_t>(modulus);
    int64_t newR = static_cast<int64_t>(a);

    while (newR != 0) {
        const int64_t q = r / newR;

        const int64_t tempT = t - q * newT;
        t = newT;
        newT = tempT;

        const int64_t tempR = r - q * newR;
        r = newR;
        newR = tempR;
    }

    if (r != 1) {
        throw invalid_argument("Modular inverse does not exist");
    }

    if (t < 0) {
        t += static_cast<int64_t>(modulus);
    }

    return static_cast<Number>(t);
}

}  // namespace

Signature sign(Number hash, const KeyPair& keys, Number k) {
    const Number p = keys.publicKey.p;

    if (p < 5 || k < 1 || k >= p - 1 || gcd(k, p - 1) != 1) {
        throw invalid_argument("Invalid signature nonce");
    }

    const Number r = modPow(keys.publicKey.g, k, p);
    const Number kInverse = modInverse(k, p - 1);

    // s = k^(-1) * (hash - x*r) mod (p - 1).
    const Number modulus = p - 1;
    const Number hashPart = hash % modulus;
    const Number xrPart = ((keys.privateKey % modulus) * r) % modulus;

    const Number difference = (hashPart + modulus - xrPart) % modulus;

    const Number s = (kInverse * difference) % modulus;

    return {r, s};
}

bool verify(Number hash, const Signature& signature, const PublicKey& key) {
    const Number p = key.p;

    if (p < 5 || signature.r < 1 || signature.r >= p || signature.s >= p - 1) {
        return false;
    }

    const Number left = modPow(key.g, hash, p);

    const Number right = (modPow(key.y, signature.r, p) * modPow(signature.r, signature.s, p)) % p;

    return left == right;
}

}  // namespace elgamal

#include "elgamal.h"
#include <stdexcept>

namespace elgamal {

Number modPow(Number base, Number exponent, Number modulus) {
    if (modulus < 2) {
        throw std::invalid_argument("Modulus must be at least 2");
    }

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
    if (p < 5 || g < 2 || g >= p ||
        x < 1 || x >= p - 1) {
        throw std::invalid_argument("Invalid ElGamal parameters");
    }

    KeyPair keys;
    keys.publicKey = {p, g, modPow(g, x, p)};
    keys.privateKey = x;

    return keys;
}

Ciphertext encrypt(Number message, const PublicKey& key, Number k) {
    if (key.p < 5 || key.g < 2 || key.g >= key.p ||
        key.y < 1 || key.y >= key.p ||
        message >= key.p || k < 1 || k >= key.p - 1) {
        throw std::invalid_argument("Invalid encryption parameters");
    }

    const Number c1 = modPow(key.g, k, key.p);
    const Number shared = modPow(key.y, k, key.p);
    const Number c2 = (message * shared) % key.p;

    return {c1, c2};
}

Number decrypt(const Ciphertext& ciphertext, const KeyPair& key) {
    const Number p = key.publicKey.p;

    if (p < 5 || ciphertext.c1 < 1 ||
        ciphertext.c1 >= p || ciphertext.c2 >= p) {
        throw std::invalid_argument("Invalid ciphertext");
    }

    const Number shared =
        modPow(ciphertext.c1, key.privateKey, p);

    // Find the multiplicative inverse of shared modulo p.
    // This implementation assumes p is prime.
    const Number inverse = modPow(shared, p - 2, p);

    return (ciphertext.c2 * inverse) % p;
}

}  // namespace elgamal

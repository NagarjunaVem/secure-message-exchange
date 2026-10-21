#include "elgamal.h"
#include <cassert>
#include <iostream>

// Author: V. Nagarjuna Reddy
// Roll Number: 20243315
// Educational ElGamal encryption/decryption test.

using namespace std;

int main() {
    using namespace elgamal;

    // Small educational test parameters.
    const Number p = 467;
    const Number g = 2;
    const Number x = 127;

    const KeyPair keys = makeKeyPair(p, g, x);

    const Number plaintext = 123;
    const Number k = 53;

    const Ciphertext ciphertext = encrypt(plaintext, keys.publicKey, k);

    const Number recovered = decrypt(ciphertext, keys);

    cout << "ElGamal Test\n";
    cout << "Public key (p, g, y): " << keys.publicKey.p << ", " << keys.publicKey.g << ", " << keys.publicKey.y << '\n';

    cout << "Ciphertext (c1, c2): " << ciphertext.c1 << ", " << ciphertext.c2 << '\n';

    cout << "Original message: " << plaintext << '\n';
    cout << "Decrypted message: " << recovered << '\n';

    assert(recovered == plaintext);

    // Test modular exponentiation.
    assert(modPow(2, 10, 1000) == 24);

    cout << "All ElGamal tests passed!\n";

    const Number hash = 234;
    const Signature signature = sign(hash, keys, 53);

    assert(verify(hash, signature, keys.publicKey));
    assert(!verify(hash + 1, signature, keys.publicKey));

    cout << "Digital signature test passed!\n";

    return 0;
}

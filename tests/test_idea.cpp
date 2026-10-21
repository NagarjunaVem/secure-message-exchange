
/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 * Purpose: Test Simplified IDEA encryption and decryption.
 */

#include "simplified_idea.h"

#include <cstdint>
#include <iomanip>
#include <iostream>

using namespace std;

int main() {
    // Known-answer test from the supplied Simplified IDEA reference.
    constexpr uint16_t plaintext = 0x9CAC;
    constexpr uint32_t key = 0xDC6F3F59;
    constexpr uint16_t expected_ciphertext = 0xBB4B;

    const uint16_t ciphertext = simplified_idea::encrypt(plaintext, key);

    const uint16_t recovered = simplified_idea::decrypt(ciphertext, key);

    cout << hex << uppercase << setfill('0');

    cout << "Simplified IDEA Test\n";
    cout << "Author: Vem Nagarjuna Reddy\n";
    cout << "Roll Number: 20243315\n\n";

    cout << "Plaintext:  " << setw(4) << plaintext << '\n';

    cout << "Secret key: " << setw(8) << key << '\n';

    cout << "Ciphertext: " << setw(4) << ciphertext << '\n';

    cout << "Expected:   " << setw(4) << expected_ciphertext << '\n';

    cout << "Decrypted:  " << setw(4) << recovered << '\n';

    if (ciphertext != expected_ciphertext) {
        cerr << "\nFAIL: Ciphertext does not match reference.\n";
        return 1;
    }

    if (recovered != plaintext) {
        cerr << "\nFAIL: Decryption did not recover plaintext.\n";
        return 1;
    }

    cout << "\nPASS: Encryption and decryption verified.\n";
    return 0;
}

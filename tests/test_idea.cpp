
/*
 * Author: Vem Nagarjuna Reddy
 * Roll Number: 20243315
 * Purpose: Test Simplified IDEA encryption and decryption.
 */

#include "simplified_idea.h"

#include <cstdint>
#include <iomanip>
#include <iostream>

int main() {
    // Known-answer test from the supplied Simplified IDEA reference.
    constexpr uint16_t plaintext = 0x9CAC;
    constexpr uint32_t key = 0xDC6F3F59;
    constexpr uint16_t expected_ciphertext = 0xBB4B;

    const uint16_t ciphertext =
        simplified_idea::encrypt(plaintext, key);

    const uint16_t recovered =
        simplified_idea::decrypt(ciphertext, key);

    std::cout << std::hex << std::uppercase << std::setfill('0');

    std::cout << "Simplified IDEA Test\n";
    std::cout << "Author: Vem Nagarjuna Reddy\n";
    std::cout << "Roll Number: 20243315\n\n";

    std::cout << "Plaintext:  "
              << std::setw(4) << plaintext << '\n';

    std::cout << "Secret key: "
              << std::setw(8) << key << '\n';

    std::cout << "Ciphertext: "
              << std::setw(4) << ciphertext << '\n';

    std::cout << "Expected:   "
              << std::setw(4) << expected_ciphertext << '\n';

    std::cout << "Decrypted:  "
              << std::setw(4) << recovered << '\n';

    if (ciphertext != expected_ciphertext) {
        std::cerr << "\nFAIL: Ciphertext does not match reference.\n";
        return 1;
    }

    if (recovered != plaintext) {
        std::cerr << "\nFAIL: Decryption did not recover plaintext.\n";
        return 1;
    }

    std::cout << "\nPASS: Encryption and decryption verified.\n";
    return 0;
}

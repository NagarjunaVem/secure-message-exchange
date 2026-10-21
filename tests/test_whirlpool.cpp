// Author: Vem Nagarjuna Reddy
// Roll Number: 20243315
// Purpose: Test the Whirlpool hash implementation.

#include "whirlpool.h"

#include <cassert>
#include <iostream>
#include <string>

using namespace std;

int main() {
    const string message =
        "The quick brown fox jumps over the lazy dog";

    const string expected =
        "B97DE512E91E3828B40D2B0FDCE9CEB3"
        "C4A71F9BEA8D88E75C4FA854DF36725F"
        "D2B52EB6544EDCACD6F8BEDDFEA403CB"
        "55AE31F03AD62A5EF54E42EE82C3FB35";

    const string actual = crypto::whirlpoolHex(message);

    cout << "Input:    " << message << '\n';
    cout << "Expected: " << expected << '\n';
    cout << "Actual:   " << actual << '\n';

    assert(actual == expected);

    cout << "Whirlpool known-answer test passed.\n";
    return 0;
}
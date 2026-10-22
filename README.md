# Secure Message Exchange

**Language:** C++17  
**Author:** Vem Nagarjuna Reddy  
**Roll Number:** 20243315

## Project overview

This project has a client and a server that exchange a message over TCP. The
client encrypts the message with Simplified IDEA, encrypts the IDEA key with
the server's ElGamal public key, and signs the message hash with its ElGamal
private key. The server decrypts the key and message, calculates the hash, and
checks the signature.

The project uses the C++ standard library and the socket API built into the
operating system. It does not need third-party libraries. Windows builds use
Winsock, which is included with Windows.

## Algorithms

- **Simplified IDEA:** encrypts and decrypts 16-bit blocks with a 32-bit key.
  The program prints the intermediate values for each block.
- **ElGamal:** creates public and private keys, encrypts the IDEA key, and
  creates and checks the digital signature.
- **Whirlpool:** calculates a 512-bit hash. Its implementation is included in
  this project.

The example values `p=467`, `g=2`, and `x=127` are suitable for a small local
demonstration. Both the client and server can use these values. They are too
small for protecting real messages.

## Build on Windows with MSYS2

Open PowerShell in the project folder. Make sure the MSYS2 MinGW-w64 compiler
is available as `g++`, then run:

```powershell
New-Item -ItemType Directory -Force build | Out-Null
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude src\main_server.cpp src\socket_utils.cpp src\exchange_protocol.cpp src\secure_exchange.cpp src\simplified_idea.cpp src\elgamal.cpp src\whirlpool.cpp -lws2_32 -o build\server.exe
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude src\main_client.cpp src\socket_utils.cpp src\exchange_protocol.cpp src\secure_exchange.cpp src\simplified_idea.cpp src\elgamal.cpp src\whirlpool.cpp -lws2_32 -o build\client.exe
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude src\crypto_demo.cpp src\secure_exchange.cpp src\simplified_idea.cpp src\elgamal.cpp src\whirlpool.cpp -o build\crypto_demo.exe
```

`-lws2_32` links the Windows socket API. It is a Windows system library, not a
third-party library.

## Build on Linux

The same source also uses POSIX sockets on Linux. From the project folder, run:

```sh
mkdir -p build
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude src/main_server.cpp src/socket_utils.cpp src/exchange_protocol.cpp src/secure_exchange.cpp src/simplified_idea.cpp src/elgamal.cpp src/whirlpool.cpp -o build/server
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude src/main_client.cpp src/socket_utils.cpp src/exchange_protocol.cpp src/secure_exchange.cpp src/simplified_idea.cpp src/elgamal.cpp src/whirlpool.cpp -o build/client
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude src/crypto_demo.cpp src/secure_exchange.cpp src/simplified_idea.cpp src/elgamal.cpp src/whirlpool.cpp -o build/crypto_demo
```

## Run the programs

For a one-click Windows run, double-click `run.bat` in the project folder. It
builds the client and server, opens a server window, then opens a client window.
Enter the server values first, followed by the message and client values. The
MSYS2 MinGW-w64 `g++` compiler must be available on `PATH`.

To run them manually:

1. Open one terminal and start the server: `.\build\server.exe`.
2. Enter the server values for `p`, `g`, and `x` when prompted.
3. Open another terminal and start the client: `.\build\client.exe`.
4. Enter a message, a decimal IDEA key from `0` to `4294967295`, and the client
   values for `p`, `g`, and `x`.

The default port is `8080`. You can give the server a port, for example
`.\build\server.exe 9000`, and give the client the server address and port,
for example `.\build\client.exe 127.0.0.1 9000`.

To run the cryptographic steps without a network connection, start
`.\build\crypto_demo.exe`.

## Files and main functions

- `src/main_client.cpp`: reads the message and client keys, prepares the
  encrypted packet, sends it, and displays the server's verification result.
- `src/main_server.cpp`: reads the server keys, sends its public key, processes
  the client's packet, and displays the recovered message and signature result.
- `src/crypto_demo.cpp`: runs the cryptographic exchange in one process.
- `src/simplified_idea.cpp`: `encrypt` and `decrypt` handle one block;
  `generate_subkeys` creates the round keys. Declarations are in
  `include/simplified_idea.h`.
- `src/elgamal.cpp`: `makeKeyPair`, `encrypt`, `decrypt`, `sign`, and `verify`
  implement the ElGamal operations. `modPow` calculates a modular power.
  Declarations are in `include/elgamal.h`.
- `src/whirlpool.cpp`: `whirlpool` calculates the digest and `whirlpoolHex`
  returns it as hexadecimal text. Declarations are in `include/whirlpool.h`.
- `src/secure_exchange.cpp`: `prepareClientPacket` creates the encrypted
  message packet; `processClientPacket` decrypts it and verifies the signature.
  Declarations are in `include/secure_exchange.h`.
- `src/exchange_protocol.cpp`: `encode...` functions convert data into network
  bytes, and `decode...` functions read the bytes back. Declarations are in
  `include/exchange_protocol.h`.
- `src/socket_utils.cpp`: `TcpSocket` connects, listens, accepts, sends, and
  receives. `sendFrame` and `receiveFrame` send and read length-prefixed data.
  Declarations are in `include/socket_utils.h`.
- `tests/`: small checks for IDEA encryption/decryption, ElGamal operations,
  and the Whirlpool result.

## Build the component checks

Run these from the project folder after creating `build`:

```powershell
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude tests\test_idea.cpp src\simplified_idea.cpp -o build\test_idea.exe
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude tests\test_elgamal.cpp src\elgamal.cpp -o build\test_elgamal.exe
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude tests\test_whirlpool.cpp src\whirlpool.cpp -o build\test_whirlpool.exe
```

Run each check with `.\build\test_idea.exe`, `.\build\test_elgamal.exe`,
and `.\build\test_whirlpool.exe`.

# Secure Message Exchange

**Language:** C++17  
**Author:** Vem Nagarjuna Reddy  
**Roll Number:** 20243315

## Overview

A command-line client-server application for secure message exchange using TCP sockets, Simplified IDEA, ElGamal encryption and digital signatures, and a Whirlpool hash implementation written from scratch.

## Features

- TCP client-server communication
- Symmetric message encryption and decryption
- Asymmetric encryption of the symmetric secret key
- Whirlpool 512-bit hashing
- Digital signature generation and verification
- Intermediate cryptographic output for educational evaluation

## Project Structure

- `src/`: Application and implementation files
- `include/`: Header files
- `tests/`: Component tests
- `screenshots/`: Genuine execution screenshots

## Build

The current implementation can be built in WSL 2 with Ubuntu's C++ compiler. In the WSL terminal, install the compiler if needed:

```bash
sudo apt update
sudo apt install build-essential
```

From the repository directory, compile the implemented TCP server:

```bash
mkdir -p build
g++ -std=c++17 -Wall -Wextra -Wpedantic src/main_server.cpp -o build/server
```

If the repository is on the Windows C: drive, its usual WSL path is `/mnt/c/Users/NAGARJUNA/Desktop/secure-message-exchange`. It is also fine to clone the repository into the WSL filesystem and build there.

The current source tree does not yet contain an implemented client or cryptographic modules: those source and header files are empty. Therefore, this command builds the server only, not the complete secure-message-exchange application.

## Run

Start the server in one WSL terminal:

```bash
./build/server
```

It listens on TCP port 8080 and handles one client connection before exiting. While it is listening, connect from a second WSL terminal to verify the request and reply:

```bash
python3 - <<'PY'
import socket

with socket.create_connection(("127.0.0.1", 8080)) as client:
    client.sendall(b"Hello from WSL")
    print(client.recv(1024).decode())
PY
```

The client prints `Hello from server!`; the server prints the received message and then stops. Start the server again for another connection. If port 8080 is already in use, stop the other process or change the port in `src/main_server.cpp` and rebuild.

## Testing

The Python socket check above exercises the implemented server in WSL. The cryptographic test files are currently empty and do not yet provide runnable tests.

## Limitations

This is an educational implementation. Do not use it to protect real confidential data without a security review.

## Assignment Output

Include the required client-side and server-side output fields and links to the genuine execution screenshots.

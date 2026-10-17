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

Document the exact C++17 compiler commands and any platform-specific socket settings used by the project.

## Run

1. Start the server.
2. Start the client.
3. Enter the message and test key.
4. Inspect the encryption and verification output.

## Testing

Document the known-answer tests for Whirlpool, the encryption/decryption round-trip tests, and signature-tampering tests.

## Limitations

This is an educational implementation. Do not use it to protect real confidential data without a security review.

## Assignment Output

Include the required client-side and server-side output fields and links to the genuine execution screenshots.

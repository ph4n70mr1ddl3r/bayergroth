# Bayer-Groth 2012 Shuffle Protocol

A C++ implementation of the Bayer-Groth 2012 shuffle protocol, a zero-knowledge proof scheme for verifiable shuffles of ElGamal ciphertexts.

## Overview

This library implements a **verifiable shuffle** using the Bayer-Groth 2012 protocol, which provides cryptographic proof that a shuffled output is a valid permutation of the input without revealing the permutation itself.

### Key Features

- **Zero-Knowledge Proofs**: Shuffle proofs do not reveal the permutation
- **ElGamal Encryption**: Standard cryptographic primitives for ciphertexts
- **Secure Memory Handling**: Sensitive data is securely cleared after use
- **Constant-Time Comparisons**: Protection against timing attacks

### Application

The included demo application implements a **two-player card shuffling protocol** where:
1. Both players generate independent key pairs with compatible parameters
2. Cards are encrypted and shuffled by Player 1 with a zero-knowledge proof
3. Player 2 verifies the shuffle, re-encrypts with their key, and shuffles again
4. Cards are revealed cooperatively using threshold decryption
5. **Neither player alone can know the card order**

## Security Properties

### What This Protocol Provides

- **Shuffle Correctness**: The verifier can confirm the output is a valid shuffled version of the input
- **Perfect Hiding**: The shuffle reveals no information about the permutation
- **Public Verifiability**: Anyone with the public key can verify the shuffle proof

### Security Parameters

| Parameter | Description |
|-----------|-------------|
| 256-bit | Minimum recommended for legacy compatibility |
| 384-bit | Recommended for general use |
| 512-bit | For high-security applications |

The security parameter determines the size of the cryptographic primes (p, q) used in key generation.

### Limitations

- **Not for Production**: This implementation is for educational and research purposes
- **No Formal Audit**: Has not undergone formal cryptographic audit
- **Side Channels**: May not be fully hardened against all side-channel attacks
- **Constant-Time**: Some operations may not be constant-time on all platforms

## Building

### Prerequisites

- C++17 compiler
- CMake 3.16+
- OpenSSL
- GMP (GNU Multiple Precision Arithmetic Library)

### Build Instructions

```bash
mkdir build && cd build
cmake ..
make
```

### Running Tests

```bash
ctest
```

### Running Demo

```bash
./bg12_card_shuffle
```

## Usage Example

```cpp
#include "bayer_groth_shuffle.h"

using namespace BayerGroth;

// Generate key pair
BayerGrothShuffle shuffler(256);
KeyPair keyPair = shuffler.generateKeyPair();

// Encrypt messages
std::vector<Ciphertext> input;
input.push_back(shuffler.encrypt(keyPair.pk, mpz_class(42)));

// Shuffle with proof
ShuffleProof proof;
std::vector<size_t> perm = {0}; // Permutation for single element
std::vector<mpz_class> rand = {shuffler.generateRandomNumber(keyPair.pk.q)};
auto output = shuffler.shuffle(keyPair.pk, input, rand, perm, proof);

// Verify
bool valid = shuffler.verify(keyPair.pk, input, output, proof);
```

## API Reference

### BayerGrothShuffle Class

- `generateKeyPair()`: Creates a new ElGamal key pair
- `encrypt(pk, message)`: Encrypts a message with the public key
- `decrypt(pk, sk, ct)`: Decrypts a ciphertext with the secret key
- `shuffle(pk, input, randomness, permutation, proof)`: Performs a verifiable shuffle
- `verify(pk, input, output, proof)`: Verifies a shuffle proof

### Key Structures

- `PublicKey`: Contains ElGamal parameters (g, h, q, p)
- `KeyPair`: Public key + secret key
- `Ciphertext`: Pair (a, b) representing encrypted message
- `ShuffleProof`: Zero-knowledge proof of shuffle correctness

## File Structure

```
bayergroth/
├── CMakeLists.txt
├── README.md
├── .clang-format
├── src/
│   ├── CMakeLists.txt
│   ├── bayer_groth_shuffle.h
│   ├── bayer_groth_shuffle.cpp
│   ├── card_shuffle_protocol.h
│   ├── card_shuffle_protocol.cpp
│   ├── crypto_utils.h
│   └── crypto_utils.cpp
├── apps/
│   ├── CMakeLists.txt
│   └── main.cpp
├── tests/
│   ├── CMakeLists.txt
│   └── test_bg12.cpp
└── cmake/
    └── BayerGrothShuffleConfig.cmake.in
```

## References

- Bayer, S., & Groth, J. (2012). Efficient Zero-Knowledge Argument for the Correctness of a Shuffle. EUROCRYPT 2012.
- ElGamal, T. (1985). A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms. IEEE Transactions on Information Theory.

## License

See repository license file.

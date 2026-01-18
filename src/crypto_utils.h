#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <cstddef>
#include <cstring>
#include <openssl/crypto.h>

void getRandomBytesFromDevice(unsigned char* buffer, size_t size);

[[nodiscard]] std::vector<unsigned char> getRandomBytesFromDevice(size_t size);

void secureClearBytes(unsigned char* buffer, size_t size);

template<typename T>
void secureClear(T& obj) {
    OPENSSL_cleanse(&obj, sizeof(T));
}

#endif // CRYPTO_UTILS_H

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <cstddef>

void getRandomBytesFromDevice(unsigned char* buffer, size_t size);

std::vector<unsigned char> getRandomBytesFromDevice(size_t size);

void secureClearBytes(unsigned char* buffer, size_t size);

template<typename T>
void secureClear(T& obj) {
    volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(&obj);
    for (size_t i = 0; i < sizeof(T); ++i) {
        p[i] = 0;
    }
}

#endif // CRYPTO_UTILS_H

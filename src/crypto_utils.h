#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <cstddef>

void getRandomBytesFromDevice(unsigned char* buffer, size_t size);

std::vector<unsigned char> getRandomBytesFromDevice(size_t size);

#endif // CRYPTO_UTILS_H

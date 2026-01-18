#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <cstddef>
#include <cstring>
#include <openssl/crypto.h>
#include <gmpxx.h>

void getRandomBytesFromDevice(unsigned char* buffer, size_t size);

[[nodiscard]] std::vector<unsigned char> getRandomBytesFromDevice(size_t size);

void secureClearBytes(unsigned char* buffer, size_t size);

template<typename T>
void secureClear(T& obj) {
    OPENSSL_cleanse(&obj, sizeof(T));
}

template<>
inline void secureClear<mpz_class>(mpz_class& obj) {
    if (obj != 0) {
        mpz_class zero(0);
        mpz_set(obj.get_mpz_t(), zero.get_mpz_t());
    }
}

#endif // CRYPTO_UTILS_H

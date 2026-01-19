#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <cstddef>
#include <cstring>
#include <openssl/crypto.h>
#include <gmpxx.h>
#include <gmp.h>

#include "bayer_groth_shuffle.h"

void getRandomBytesFromDevice(unsigned char* buffer, size_t size);

[[nodiscard]] std::vector<unsigned char> getRandomBytesFromDevice(size_t size) noexcept(false);

void secureClearBytes(unsigned char* buffer, size_t size) noexcept;

template<typename T>
void secureClear(T& obj) noexcept {
    OPENSSL_cleanse(&obj, sizeof(T));
}

template<>
inline void secureClear<mpz_class>(mpz_class& obj) noexcept {
    mpz_ptr mpz = obj.get_mpz_t();
    if (mpz) {
        size_t limb_count = mpz_size(mpz);
        if (limb_count > 0) {
            mp_limb_t* limbs = mpz_limbs_write(mpz, limb_count);
            if (limbs) {
                OPENSSL_cleanse(limbs, limb_count * sizeof(mp_limb_t));
                mpz_limbs_finish(mpz, 0);
            }
        }
        mpz_set_ui(mpz, 0);
    }
}

inline void secureClearCiphertext(BayerGroth::Ciphertext& ct) noexcept {
    secureClear(ct.a);
    secureClear(ct.b);
}

#endif // CRYPTO_UTILS_H

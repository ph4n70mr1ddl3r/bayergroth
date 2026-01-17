#include "crypto_utils.h"
#include <stdexcept>
#include <openssl/rand.h>

void getRandomBytesFromDevice(unsigned char* buffer, size_t size) {
    int result = RAND_bytes(buffer, size);

    if (result != 1) {
        FILE* f = fopen("/dev/urandom", "rb");
        if (f) {
            size_t read_count = fread(buffer, 1, size, f);
            fclose(f);
            if (read_count != size) {
                throw std::runtime_error("Failed to read sufficient random bytes from /dev/urandom");
            }
        } else {
            throw std::runtime_error("Failed to read from /dev/urandom and OpenSSL RAND_bytes failed");
        }
    }
}

std::vector<unsigned char> getRandomBytesFromDevice(size_t size) {
    std::vector<unsigned char> buffer(size);
    getRandomBytesFromDevice(buffer.data(), size);
    return buffer;
}

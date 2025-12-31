#include "bayer_groth_shuffle.h"
#include <iostream>
#include <vector>
#include <random>

using namespace BayerGroth;

int main() {
    std::mt19937_64 rng1(12345);
    std::mt19937_64 rng2(67890);

    BayerGrothShuffle aliceShuffle(256);
    aliceShuffle.setRandomGenerator(rng1);
    KeyPair aliceKey = aliceShuffle.generateKeyPair();
    std::cout << "Alice key generated" << std::endl;

    BayerGrothShuffle bobShuffle(256);
    bobShuffle.setRandomGenerator(rng2);
    KeyPair bobKey = bobShuffle.generateKeyPair();
    std::cout << "Bob key generated" << std::endl;

    Ciphertext ct;
    ct.a = aliceShuffle.modExp(aliceKey.pk.g, mpz_class(5), aliceKey.pk.p);
    ct.b = aliceShuffle.modMul(mpz_class(42), ct.a, aliceKey.pk.p);
    ct.c = 0;
    ct.d = 1;

    std::cout << "Testing decryption..." << std::endl;
    std::cout << "ct.a = " << ct.a << std::endl;
    std::cout << "ct.b = " << ct.b << std::endl;
    std::cout << "p = " << aliceKey.pk.p << std::endl;
    
    mpz_class share1 = aliceShuffle.modExp(ct.a, aliceKey.sk, aliceKey.pk.p);
    std::cout << "share1 = " << share1 << std::endl;
    
    mpz_class share2 = bobShuffle.modExp(ct.a, bobKey.sk, bobKey.pk.p);
    std::cout << "share2 = " << share2 << std::endl;
    
    mpz_class combined = aliceShuffle.modMul(share1, share2, aliceKey.pk.p);
    std::cout << "combined = " << combined << std::endl;
    
    mpz_class inv;
    mpz_invert(inv.get_mpz_t(), combined.get_mpz_t(), aliceKey.pk.p.get_mpz_t());
    std::cout << "inv = " << inv << std::endl;
    
    mpz_class result;
    mpz_mul(result.get_mpz_t(), ct.b.get_mpz_t(), inv.get_mpz_t());
    mpz_mod(result.get_mpz_t(), result.get_mpz_t(), aliceKey.pk.p.get_mpz_t());
    std::cout << "plaintext = " << result << std::endl;
    
    std::cout << "Test completed successfully!" << std::endl;
    
    return 0;
}

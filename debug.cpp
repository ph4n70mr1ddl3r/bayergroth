#include "bayer_groth_shuffle.h"
#include <iostream>
#include <random>

using namespace BayerGroth;

int main() {
    std::mt19937_64 rng1(12345);

    BayerGrothShuffle shuffle(256);
    shuffle.setRandomGenerator(rng1);
    KeyPair aliceKey = shuffle.generateKeyPair();
    std::cout << "Key generated" << std::endl;
    
    Ciphertext ct;
    ct.a = shuffle.modExp(aliceKey.pk.g, mpz_class(5), aliceKey.pk.p);
    ct.b = shuffle.modMul(mpz_class(42), ct.a, aliceKey.pk.p);
    ct.c = 0;
    ct.d = 1;
    
    std::cout << "ct.a = " << ct.a.get_str() << std::endl;
    std::cout << "ct.b = " << ct.b.get_str() << std::endl;
    std::cout << "sk = " << aliceKey.sk.get_str() << std::endl;
    std::cout << "p = " << aliceKey.pk.p.get_str() << std::endl;
    
    mpz_class share1 = shuffle.modExp(ct.a, aliceKey.sk, aliceKey.pk.p);
    std::cout << "share1 = " << share1.get_str() << std::endl;
    
    mpz_class combined = shuffle.modMul(share1, share1, aliceKey.pk.p);
    std::cout << "combined = " << combined.get_str() << std::endl;
    
    mpz_class inv;
    int result = mpz_invert(inv.get_mpz_t(), combined.get_mpz_t(), aliceKey.pk.p.get_mpz_t());
    std::cout << "invert result = " << result << std::endl;
    std::cout << "inv = " << inv.get_str() << std::endl;
    
    mpz_class plaintext;
    mpz_mul(plaintext.get_mpz_t(), ct.b.get_mpz_t(), inv.get_mpz_t());
    mpz_mod(plaintext.get_mpz_t(), plaintext.get_mpz_t(), aliceKey.pk.p.get_mpz_t());
    std::cout << "plaintext = " << plaintext.get_str() << std::endl;
    
    std::cout << "Success!" << std::endl;
    return 0;
}

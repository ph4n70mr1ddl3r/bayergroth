#include "bayer_groth_shuffle.h"
#include <iostream>

int main() {
    std::mt19937_64 rng1(12345);
    std::mt19937_64 rng2(67890);
    
    BayerGroth::BayerGrothShuffle shuffle(256);
    shuffle.setRandomGenerator(rng1);
    auto aliceKey = shuffle.generateKeyPair();
    std::cout << "Alice key generated" << std::endl;
    
    shuffle.setRandomGenerator(rng2);
    auto bobKey = shuffle.generateKeyPair();
    std::cout << "Bob key generated" << std::endl;
    
    shuffle.setRandomGenerator(rng1);
    auto ct = shuffle.encrypt(aliceKey.pk, mpz_class(42));
    std::cout << "Encrypted" << std::endl;
    
    auto share1 = shuffle.modExp(ct.a, aliceKey.sk, aliceKey.pk.p);
    std::cout << "share1 computed" << std::endl;
    
    shuffle.setRandomGenerator(rng2);
    auto share2 = shuffle.modExp(ct.a, bobKey.sk, bobKey.pk.p);
    std::cout << "share2 computed" << std::endl;
    
    shuffle.setRandomGenerator(rng1);
    auto combined = shuffle.modMul(share1, share2, aliceKey.pk.p);
    std::cout << "combined computed" << std::endl;
    
    auto inv = shuffle.modInv(combined, aliceKey.pk.p);
    std::cout << "inv computed" << std::endl;
    
    auto m = shuffle.modMul(ct.b, inv, aliceKey.pk.p);
    std::cout << "Decrypted: " << m << std::endl;
    
    std::cout << "Success!" << std::endl;
    return 0;
}

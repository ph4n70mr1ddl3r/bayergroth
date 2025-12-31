#include "bayer_groth_shuffle.h"
#include <iostream>

int main() {
    BayerGroth::BayerGrothShuffle shuffle(256);
    auto keyPair = shuffle.generateKeyPair();
    std::cout << "Key generated" << std::endl;
    
    auto ct = shuffle.encrypt(keyPair.pk, mpz_class(42));
    std::cout << "Encrypted" << std::endl;
    
    mpz_class m = shuffle.modMul(ct.b, shuffle.modInv(shuffle.modExp(ct.a, keyPair.sk, keyPair.pk.p), keyPair.pk.p), keyPair.pk.p);
    std::cout << "Decrypted: " << m << std::endl;
    
    std::cout << "Success!" << std::endl;
    return 0;
}

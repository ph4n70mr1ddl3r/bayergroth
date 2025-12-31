#include "bayer_groth_shuffle.h"
#include <iostream>

int main() {
    BayerGroth::BayerGrothShuffle shuffle(256);
    auto keyPair = shuffle.generateKeyPair();
    std::cout << "Key generated" << std::endl;
    std::cout << "p = " << keyPair.pk.p.get_str() << std::endl;
    std::cout << "Success!" << std::endl;
    return 0;
}

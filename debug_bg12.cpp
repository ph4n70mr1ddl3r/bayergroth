#include "bayer_groth_shuffle.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <chrono>

using namespace BayerGroth;

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  Bayer-Groth 2012 Shuffle Protocol" << std::endl;
    std::cout << "  Debug Test" << std::endl;
    std::cout << "========================================" << std::endl;

    auto start = std::chrono::high_resolution_clock::now();

    std::mt19937_64 rng(12345);
    
    BayerGrothShuffle bg12(64);
    bg12.setRandomGenerator(rng);

    std::cout << "\n[1] Key Generation (64-bit security)" << std::endl;
    KeyPair key = bg12.generateKeyPair();
    std::cout << "    Generated key pair" << std::endl;
    std::cout << "    |p| = " << mpz_sizeinbase(key.pk.p.get_mpz_t(), 2) << " bits" << std::endl;
    std::cout << "    |q| = " << mpz_sizeinbase(key.pk.q.get_mpz_t(), 2) << " bits" << std::endl;
    std::cout << "    p = " << key.pk.p << std::endl;
    std::cout << "    q = " << key.pk.q << std::endl;
    std::cout << "    g = " << key.pk.g << std::endl;
    std::cout << "    h = " << key.pk.h << std::endl;

    std::cout << "\n[1.5] Testing generateRandomNumber" << std::endl;
    mpz_class testRand = bg12.generateRandomNumber(key.pk.q);
    std::cout << "    Random in [0, q): " << testRand << std::endl;
    std::cout << "    q = " << key.pk.q << std::endl;

    std::cout << "\n[2] Encryption" << std::endl;
    std::cout << "    About to call encrypt..." << std::endl;
    Ciphertext ct = bg12.encrypt(key.pk, mpz_class(42));
    std::cout << "    Encrypted message: 42" << std::endl;
    
    size_t ctSize = estimateCiphertextSize(ct);
    std::cout << "    Ciphertext size: " << ctSize << " bytes" << std::endl;

    std::cout << "\n[3] Shuffle with Proof" << std::endl;
    std::vector<Ciphertext> input(1, ct);
    std::vector<int> perm = {0};
    std::vector<mpz_class> rand(1);
    rand[0] = bg12.generateRandomNumber(key.pk.q);
    ShuffleProof proof;
    
    auto shuffleStart = std::chrono::high_resolution_clock::now();
    std::vector<Ciphertext> output = bg12.shuffle(key.pk, input, rand, perm, proof);
    auto shuffleEnd = std::chrono::high_resolution_clock::now();
    auto shuffleTime = std::chrono::duration_cast<std::chrono::microseconds>(shuffleEnd - shuffleStart);
    
    size_t proofSize = estimateProofSize(proof);
    std::cout << "    Shuffle completed" << std::endl;
    std::cout << "    Proof size: " << proofSize << " bytes" << std::endl;
    std::cout << "    Time: " << shuffleTime.count() << " us" << std::endl;

    std::cout << "\n[4] Verification" << std::endl;
    auto verifyStart = std::chrono::high_resolution_clock::now();
    bool valid = bg12.verify(key.pk, input, output, proof);
    auto verifyEnd = std::chrono::high_resolution_clock::now();
    auto verifyTime = std::chrono::duration_cast<std::chrono::microseconds>(verifyEnd - verifyStart);
    
    std::cout << "    Result: " << (valid ? "VALID" : "INVALID") << std::endl;
    std::cout << "    Time: " << verifyTime.count() << " us" << std::endl;

    auto end = std::chrono::high_resolution_clock::now();
    auto total = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "\n========================================" << std::endl;
    std::cout << "  Complete!" << std::endl;
    std::cout << "========================================" << std::endl;

    std::cout << "\n[Performance Summary]" << std::endl;
    std::cout << "  Total time:      " << total.count() << " ms" << std::endl;
    std::cout << "  Ciphertext:      " << ctSize << " bytes" << std::endl;
    std::cout << "  Proof:           " << proofSize << " bytes" << std::endl;

    return 0;
}

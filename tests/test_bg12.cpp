#include "../src/bayer_groth_shuffle.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <chrono>
#include <gmpxx.h>

using namespace BayerGroth;

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  Bayer-Groth 2012 Shuffle Protocol" << std::endl;
    std::cout << "  Full Test" << std::endl;
    std::cout << "========================================" << std::endl;

    auto start = std::chrono::high_resolution_clock::now();

    std::mt19937_64 rng(12345);
    BayerGrothShuffle bg12(256);
    bg12.setRandomGenerator(rng);

    std::cout << "\n[1] Key Generation (256-bit security)" << std::endl;
    KeyPair key = bg12.generateKeyPair();
    std::cout << "    |p| = " << mpz_sizeinbase(key.pk.p.get_mpz_t(), 2) << " bits" << std::endl;
    std::cout << "    |q| = " << mpz_sizeinbase(key.pk.q.get_mpz_t(), 2) << " bits" << std::endl;
    std::cout << "    g^q = " << bg12.modExp(key.pk.g, key.pk.q, key.pk.p) << " (should be 1)" << std::endl;

    std::cout << "\n[2] Encrypt multiple messages" << std::endl;
    std::vector<Ciphertext> input;
    std::vector<mpz_class> messages = {mpz_class(1), mpz_class(2), mpz_class(3), mpz_class(42), mpz_class(100)};
    for (const auto& msg : messages) {
        Ciphertext ct = bg12.encrypt(key.pk, msg);
        input.push_back(ct);
    }
    std::cout << "    Encrypted " << input.size() << " messages" << std::endl;
    
    size_t ctSize = estimateCiphertextSize(input[0]);
    std::cout << "    Ciphertext size: " << ctSize << " bytes each" << std::endl;

    std::cout << "\n[3] Generate permutation" << std::endl;
    std::vector<size_t> perm = BayerGrothShuffle::generatePermutation(input.size(), rng);
    std::cout << "    Permutation: ";
    for (size_t i = 0; i < perm.size(); ++i) {
        std::cout << perm[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "\n[4] Generate randomness for each element" << std::endl;
    std::vector<mpz_class> randomness(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        randomness[i] = bg12.generateRandomNumber(key.pk.q);
    }
    std::cout << "    Generated " << randomness.size() << " random values" << std::endl;

    std::cout << "\n[5] Shuffle with Proof" << std::endl;
    ShuffleProof proof;
    
    auto shuffleStart = std::chrono::high_resolution_clock::now();
    std::vector<Ciphertext> output = bg12.shuffle(key.pk, input, randomness, perm, proof);
    auto shuffleEnd = std::chrono::high_resolution_clock::now();
    auto shuffleTime = std::chrono::duration_cast<std::chrono::microseconds>(shuffleEnd - shuffleStart);
    
    size_t proofSize = estimateProofSize(proof);
    std::cout << "    Shuffle completed" << std::endl;
    std::cout << "    Proof size: " << proofSize << " bytes" << std::endl;
    std::cout << "    Time: " << shuffleTime.count() << " us" << std::endl;

    std::cout << "\n[6] Verify shuffle" << std::endl;
    auto verifyStart = std::chrono::high_resolution_clock::now();
    bool valid = bg12.verify(key.pk, input, output, proof);
    auto verifyEnd = std::chrono::high_resolution_clock::now();
    auto verifyTime = std::chrono::duration_cast<std::chrono::microseconds>(verifyEnd - verifyStart);
    
    std::cout << "    Result: " << (valid ? "VALID" : "INVALID") << std::endl;
    std::cout << "    Time: " << verifyTime.count() << " us" << std::endl;

    if (valid) {
        std::cout << "\n[7] Verify decryption" << std::endl;
        bool all_correct = true;
        for (size_t i = 0; i < output.size(); ++i) {
            mpz_class decrypted = bg12.decrypt(key.pk, key.sk, output[i]);
            bool match = (decrypted == messages[perm[i]]);
            if (!match) {
                all_correct = false;
                std::cout << "      Mismatch at position " << i << ": expected " 
                          << messages[perm[i]] << ", got " << decrypted << std::endl;
            }
        }
        std::cout << "    Decryption: " << (all_correct ? "ALL CORRECT" : "ERROR") << std::endl;
    }

    std::cout << "\n[8] Edge case: Single element shuffle" << std::endl;
    {
        BayerGrothShuffle bg12_single(256);
        bg12_single.setRandomGenerator(rng);
        KeyPair key_single = bg12_single.generateKeyPair();
        Ciphertext single_ct = bg12_single.encrypt(key_single.pk, mpz_class(42));
        std::vector<Ciphertext> single_input = {single_ct};
        std::vector<size_t> single_perm = {0};
        std::vector<mpz_class> single_rand = {bg12_single.generateRandomNumber(key_single.pk.q)};
        ShuffleProof single_proof;
        std::vector<Ciphertext> single_output = bg12_single.shuffle(key_single.pk, single_input, single_rand, single_perm, single_proof);
        bool single_valid = bg12_single.verify(key_single.pk, single_input, single_output, single_proof);
        std::cout << "    Single element shuffle: " << (single_valid ? "VALID" : "INVALID") << std::endl;
        if (!single_valid) return 1;
    }

    std::cout << "\n[9] Edge case: Modified proof fails verification" << std::endl;
    {
        ShuffleProof tampered_proof = proof;
        tampered_proof.z1[0] = tampered_proof.z1[0] + mpz_class(1);
        bool tampered_valid = bg12.verify(key.pk, input, output, tampered_proof);
        std::cout << "    Tampered proof verification: " << (!tampered_valid ? "REJECTED (expected)" : "ACCEPTED (BUG!)") << std::endl;
        if (tampered_valid) {
            std::cout << "    ERROR: Tampered proof should not validate!" << std::endl;
            return 1;
        }
    }

    std::cout << "\n[10] Edge case: Wrong input size fails" << std::endl;
    {
        std::vector<Ciphertext> wrong_size_input = input;
        wrong_size_input.push_back(input[0]);
        std::vector<Ciphertext> wrong_size_output = output;
        bool size_mismatch = bg12.verify(key.pk, wrong_size_input, wrong_size_output, proof);
        std::cout << "    Different sized vectors rejected: " << (!size_mismatch ? "YES (expected)" : "NO (BUG!)") << std::endl;
        if (size_mismatch) {
            std::cout << "    ERROR: Different sized inputs should not validate!" << std::endl;
            return 1;
        }
    }

    std::cout << "\n[11] Edge case: Constant-time comparison works" << std::endl;
    {
        mpz_class a(12345);
        mpz_class b(12345);
        mpz_class c(67890);
        bool same = BayerGrothShuffle::constantTimeEquals(a, b);
        bool diff = BayerGrothShuffle::constantTimeEquals(a, c);
        std::cout << "    Equal values compare equal: " << (same ? "YES" : "NO") << std::endl;
        std::cout << "    Different values compare different: " << (!diff ? "YES" : "NO") << std::endl;
        if (!same || diff) {
            std::cout << "    ERROR: constantTimeEquals not working correctly!" << std::endl;
            return 1;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto total = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "\n========================================" << std::endl;
    std::cout << "  Complete!" << std::endl;
    std::cout << "========================================" << std::endl;

    std::cout << "\n[Performance Summary]" << std::endl;
    std::cout << "  Total time:      " << total.count() << " ms" << std::endl;
    std::cout << "  Ciphertexts:     " << input.size() << " x " << ctSize << " bytes" << std::endl;
    std::cout << "  Proof:           " << proofSize << " bytes" << std::endl;

    std::cout << "\n[BG12 Protocol Features]" << std::endl;
    std::cout << "  - ElGamal encryption" << std::endl;
    std::cout << "  - Commitment matrix A = g^S, B = h^S" << std::endl;
    std::cout << "  - Challenge-response proof (z1-z10)" << std::endl;
    std::cout << "  - Product-form verification" << std::endl;
    std::cout << "  - Zero-knowledge shuffle proof" << std::endl;

    return valid ? 0 : 1;
}

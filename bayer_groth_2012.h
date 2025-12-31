#ifndef BAYER_GROTH_2012_H
#define BAYER_GROTH_2012_H

#include <vector>
#include <string>
#include <random>
#include <gmpxx.h>

namespace BG12 {

struct PublicKey {
    mpz_class g;  // Generator
    mpz_class h;  // g^sk mod p
    mpz_class q;  // Order of group
    mpz_class p;  // Prime modulus
};

struct KeyPair {
    PublicKey pk;
    mpz_class sk;  // Secret key
};

struct Ciphertext {
    mpz_class a;  // g^r
    mpz_class b;  // h^r * m
    mpz_class c;
    mpz_class d;
};

struct ShuffleProof {
    std::vector<std::vector<mpz_class>> A;  // Commitment matrix (g side)
    std::vector<std::vector<mpz_class>> B;  // Commitment matrix (h side)
    std::vector<mpz_class> z1;  // Response for new randomness
    std::vector<mpz_class> z2;  // Response for old randomness  
    std::vector<mpz_class> z3;  // Response for permutation column sums
    std::vector<mpz_class> z4;  // Response for permutation row sums
    std::vector<mpz_class> z5;  // Response for permutation randomness
    std::vector<mpz_class> z6;  // Response for permutation randomness
    std::vector<mpz_class> z7;  // Response for new randomness
    std::vector<mpz_class> z8;  // Response for new randomness
    std::vector<mpz_class> z9;  // Response for message mask
    std::vector<mpz_class> z10; // Response for permutation randomness
    mpz_class t;  // Challenge-dependent value for A
    mpz_class u;  // Challenge-dependent value for B
};

class BayerGroth2012 {
public:
    BayerGroth2012(int securityParam = 256);
    ~BayerGroth2012();

    KeyPair generateKeyPair();
    Ciphertext encrypt(const PublicKey& pk, const mpz_class& message);
    Ciphertext reEncrypt(const PublicKey& pk, const Ciphertext& ct, const mpz_class& r);
    
    std::vector<Ciphertext> shuffle(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<mpz_class>& randomness,
        const std::vector<int>& permutation,
        ShuffleProof& proof);

    bool verify(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const ShuffleProof& proof);

    void setRandomGenerator(std::mt19937_64& rng);
    std::mt19937_64* getRandomGenerator() { return randomGen; }
    
    // Make computeChallenge public for testing
    mpz_class computeChallenge(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const ShuffleProof& proof);

    // Static utility functions
    static mpz_class modExp(const mpz_class& base, const mpz_class& exp, const mpz_class& mod);
    static mpz_class modInv(const mpz_class& a, const mpz_class& mod);
    static mpz_class modAdd(const mpz_class& a, const mpz_class& b, const mpz_class& mod);
    static mpz_class modSub(const mpz_class& a, const mpz_class& b, const mpz_class& mod);
    static mpz_class modMul(const mpz_class& a, const mpz_class& b, const mpz_class& mod);
    static mpz_class modDiv(const mpz_class& a, const mpz_class& b, const mpz_class& mod);
    static std::vector<int> generatePermutation(size_t n, std::mt19937_64& rng);
    static mpz_class generateRandom(const mpz_class& limit, std::mt19937_64& rng);

private:
    int securityParam;
    std::mt19937_64* randomGen;
    bool ownsRandomGen;
    PublicKey currentPk;

    mpz_class getRandomExponent();
    
    // BG12 specific functions
    void generateCommitments(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const std::vector<mpz_class>& inputRand,
        const std::vector<mpz_class>& outputRand,
        const std::vector<int>& permutation,
        ShuffleProof& proof);

    void computeResponses(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const std::vector<mpz_class>& inputRand,
        const std::vector<mpz_class>& outputRand,
        const std::vector<int>& permutation,
        const mpz_class& challenge,
        ShuffleProof& proof);

    bool verifyEquations(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const ShuffleProof& proof,
        const mpz_class& challenge);
};

// Utility functions
std::string ciphertextToString(const Ciphertext& ct);
std::string proofToString(const ShuffleProof& proof);
size_t estimateProofSize(const ShuffleProof& proof);
size_t estimateCiphertextSize(const Ciphertext& ct);

} // namespace BG12

#endif // BAYER_GROTH_2012_H

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
    std::vector<std::vector<mpz_class>> A;  // Commitment matrix g^S
    std::vector<std::vector<mpz_class>> B;  // Commitment matrix h^S
    std::vector<std::vector<mpz_class>> D;  // Pedersen commitment matrix g^alpha * h^beta
    std::vector<mpz_class> z1;  // z1[i] = r'_i + c * rho_{pi(i)}
    std::vector<mpz_class> z2;  // z2[i] = rho_i + c * (row/col sums)
    std::vector<mpz_class> z3;  // z3[i] = sum_j S[i][j] * V[i][j] = S[i][π(i)]
    std::vector<mpz_class> z4;  // z4[i] = sum_j S[j][i] * V[j][i] = S[π^{-1}(i)][i]
    std::vector<mpz_class> z5;  // z5[i] = alpha_i + c * sum_j S[i][j]
    std::vector<mpz_class> z6;  // z6[i] = beta_i + c * sum_j S[i][j]
    std::vector<mpz_class> z7;  // z7[i] = alpha'_i + c * sum_j S[j][i]
    std::vector<mpz_class> z8;  // z8[i] = beta'_i + c * sum_j S[j][i]
    mpz_class z9;   // z9 = sum_i alpha_i + c * sum_{i,j} S[i][j]
    mpz_class z10;  // z10 = sum_i beta_i + c * sum_{i,j} S[i][j]
    mpz_class t;  // t = product of (a'_i / a_i^c)
    mpz_class u;  // u = product of (b'_i / b_i^c)
    mpz_class d;  // d = commitment to permutation (product of diagonal elements)
};

class BayerGroth2012 {
public:
    BayerGroth2012(int securityParam = 256);
    ~BayerGroth2012();

    KeyPair generateKeyPair();
    Ciphertext encrypt(const PublicKey& pk, const mpz_class& message);
    Ciphertext reEncrypt(const PublicKey& pk, const Ciphertext& ct, const mpz_class& r);
    mpz_class decrypt(const PublicKey& pk, const mpz_class& sk, const Ciphertext& ct);
    
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

    // Store the S matrix and Pedersen blinding factors for response computation
    std::vector<std::vector<mpz_class>> S_matrix;
    std::vector<mpz_class> alpha_row;     // alpha_i for row commitments
    std::vector<mpz_class> beta_row;      // beta_i for row commitments
    std::vector<mpz_class> alpha_col;     // alpha'_i for column commitments
    std::vector<mpz_class> beta_col;      // beta'_i for column commitments
    mpz_class alpha_sum;                   // sum of alpha_i
    mpz_class beta_sum;                    // sum of beta_i

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

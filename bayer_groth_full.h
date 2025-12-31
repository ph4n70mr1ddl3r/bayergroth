#ifndef BAYER_GROTH_FULL_H
#define BAYER_GROTH_FULL_H

#include <vector>
#include <string>
#include <random>
#include <gmpxx.h>
#include <openssl/evp.h>

namespace BG12Full {

struct PublicKey {
    mpz_class g;
    mpz_class h;
    mpz_class q;
    mpz_class p;
};

struct KeyPair {
    PublicKey pk;
    mpz_class sk;
};

struct Ciphertext {
    mpz_class a;
    mpz_class b;
};

struct ShuffleProof {
    std::vector<std::vector<mpz_class>> A;
    std::vector<std::vector<mpz_class>> B;
    std::vector<std::vector<mpz_class>> D;
    std::vector<mpz_class> z1;
    std::vector<mpz_class> z2;
    std::vector<mpz_class> z3;
    std::vector<mpz_class> z4;
    std::vector<mpz_class> z5;
    std::vector<mpz_class> z6;
    std::vector<mpz_class> z7;
    std::vector<mpz_class> z8;
    mpz_class z9;
    mpz_class z10;
    mpz_class t;
    mpz_class u;
};

class BayerGrothFull {
public:
    BayerGrothFull(int securityParam = 256);
    ~BayerGrothFull();

    KeyPair generateKeyPair();
    Ciphertext encrypt(const PublicKey& pk, const mpz_class& message, const mpz_class& randomness);
    Ciphertext reEncrypt(const PublicKey& pk, const Ciphertext& ct, const mpz_class& r);

    std::vector<Ciphertext> shuffle(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<mpz_class>& inputRand,
        const std::vector<int>& permutation,
        ShuffleProof& proof);

    bool verify(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const ShuffleProof& proof);

    void setRandomGenerator(std::mt19937_64& rng);

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

    std::vector<std::vector<mpz_class>> S_matrix;
    std::vector<mpz_class> alpha_row;
    std::vector<mpz_class> beta_row;
    std::vector<mpz_class> alpha_col;
    std::vector<mpz_class> beta_col;

    mpz_class getRandomExponent();

    void generateCommitments(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const std::vector<mpz_class>& inputRand,
        const std::vector<mpz_class>& outputRand,
        const std::vector<int>& permutation,
        ShuffleProof& proof);

    mpz_class computeChallenge(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const ShuffleProof& proof);

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

size_t estimateCiphertextSize(const Ciphertext& ct);
size_t estimateProofSize(const ShuffleProof& proof);
std::string ciphertextToString(const Ciphertext& ct);

}
#endif

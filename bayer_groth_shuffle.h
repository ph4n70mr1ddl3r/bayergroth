#ifndef BAYER_GROTH_SHUFFLE_H
#define BAYER_GROTH_SHUFFLE_H

#include <vector>
#include <string>
#include <utility>
#include <random>
#include <gmpxx.h>

namespace BayerGroth {

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
    mpz_class c;
    mpz_class d;
};

struct ShuffleProof {
    std::vector<std::vector<mpz_class>> A;
    std::vector<std::vector<mpz_class>> B;
    std::vector<mpz_class> z1;
    std::vector<mpz_class> z2;
    std::vector<mpz_class> z3;
    std::vector<mpz_class> z4;
    std::vector<mpz_class> z5;
    std::vector<mpz_class> z6;
    std::vector<mpz_class> z7;
    std::vector<mpz_class> z8;
    std::vector<mpz_class> z9;
    std::vector<mpz_class> z10;
    mpz_class t;
    mpz_class u;
};

class BayerGrothShuffle {
public:
    BayerGrothShuffle(int securityParameter = 1024);
    ~BayerGrothShuffle();

    KeyPair generateKeyPair();
    Ciphertext encrypt(const PublicKey& pk, const mpz_class& message);
    std::vector<Ciphertext> shuffle(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<mpz_class>& randomness,
        const std::vector<int>& permutation);

    ShuffleProof prove(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const std::vector<mpz_class>& inputRand,
        const std::vector<mpz_class>& outputRand,
        const std::vector<int>& permutation);

    bool verify(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const ShuffleProof& proof);

    static std::vector<int> generatePermutation(size_t n, std::mt19937_64& rng);
    static mpz_class modExp(const mpz_class& base, const mpz_class& exp, const mpz_class& mod);
    static mpz_class modInv(const mpz_class& a, const mpz_class& mod);
    static mpz_class modAdd(const mpz_class& a, const mpz_class& b, const mpz_class& mod);
    static mpz_class modSub(const mpz_class& a, const mpz_class& b, const mpz_class& mod);
    static mpz_class modMul(const mpz_class& a, const mpz_class& b, const mpz_class& mod);
    static mpz_class modDiv(const mpz_class& a, const mpz_class& b, const mpz_class& mod);

    void setRandomGenerator(std::mt19937_64& rng);
    std::mt19937_64* getRandomGenerator() { return randomGen; }
    mpz_class generateRandomNumber(const mpz_class& limit);

private:
    int securityParam;
    std::mt19937_64* randomGen;
    bool ownsRandomGen;
    PublicKey currentPk;

    mpz_class getRandomExponent();
    std::vector<Ciphertext> reEncrypt(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<mpz_class>& randomness);
    ShuffleProof generateProof(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const std::vector<mpz_class>& inputRand,
        const std::vector<mpz_class>& outputRand,
        const std::vector<int>& permutation);
    bool checkProof(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const ShuffleProof& proof);
};

mpz_class computeHash(const std::vector<Ciphertext>& ciphers, const PublicKey& pk);
std::string ciphertextToString(const Ciphertext& ct);
std::string publicKeyToString(const PublicKey& pk);
std::string proofToString(const ShuffleProof& proof);

} // namespace BayerGroth

#endif // BAYER_GROTH_SHUFFLE_H

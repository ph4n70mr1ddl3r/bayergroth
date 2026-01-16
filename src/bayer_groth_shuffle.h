#ifndef BAYER_GROTH_SHUFFLE_H
#define BAYER_GROTH_SHUFFLE_H

#include <vector>
#include <random>
#include <gmpxx.h>
#include <openssl/rand.h>

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

    KeyPair() = default;
    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;
    KeyPair(KeyPair&&) = default;
    KeyPair& operator=(KeyPair&&) = default;
};

struct Ciphertext {
    mpz_class a;
    mpz_class b;
};

struct ShuffleProof {
    std::vector<std::vector<mpz_class>> A;
    std::vector<std::vector<mpz_class>> B;
    std::vector<std::vector<mpz_class>> D;
    std::vector<int> permutation;
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
    mpz_class d;

    ShuffleProof() = default;
    ShuffleProof(const ShuffleProof&) = default;
    ShuffleProof& operator=(const ShuffleProof&) = default;
    ShuffleProof(ShuffleProof&&) = default;
    ShuffleProof& operator=(ShuffleProof&&) = default;
};

class BayerGrothShuffle {
public:
    explicit BayerGrothShuffle(int securityParam = 256);
    ~BayerGrothShuffle() noexcept;

    void setRandomGenerator(std::mt19937_64 rng);

    [[nodiscard]] KeyPair generateKeyPair();
    [[nodiscard]] Ciphertext encrypt(const PublicKey& pk, const mpz_class& message);
    [[nodiscard]] Ciphertext reEncrypt(const PublicKey& pk, const Ciphertext& ct, const mpz_class& r);
    [[nodiscard]] mpz_class decrypt(const PublicKey& pk, const mpz_class& sk, const Ciphertext& ct);

    [[nodiscard]] std::vector<Ciphertext> shuffle(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<mpz_class>& randomness,
        const std::vector<int>& permutation,
        ShuffleProof& proof);

    [[nodiscard]] bool verify(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const ShuffleProof& proof) const;

    [[nodiscard]] mpz_class computeChallenge(
        const PublicKey& pk,
        const std::vector<Ciphertext>& input,
        const std::vector<Ciphertext>& output,
        const ShuffleProof& proof) const;

    [[nodiscard]] static mpz_class modExp(const mpz_class& base, const mpz_class& exp, const mpz_class& mod);
    [[nodiscard]] static mpz_class modInv(const mpz_class& a, const mpz_class& mod);
    [[nodiscard]] static mpz_class modAdd(const mpz_class& a, const mpz_class& b, const mpz_class& mod);
    [[nodiscard]] static mpz_class modSub(const mpz_class& a, const mpz_class& b, const mpz_class& mod);
    [[nodiscard]] static mpz_class modMul(const mpz_class& a, const mpz_class& b, const mpz_class& mod);
    [[nodiscard]] static mpz_class modDiv(const mpz_class& a, const mpz_class& b, const mpz_class& mod);

    [[nodiscard]] static mpz_class getSecureRandom(const mpz_class& limit);
    [[nodiscard]] mpz_class generateRandomNumber(const mpz_class& limit);
    [[nodiscard]] static std::vector<int> generatePermutation(size_t n, std::mt19937_64& rng);

    [[nodiscard]] static bool constantTimeEquals(const mpz_class& a, const mpz_class& b) noexcept;
    [[nodiscard]] static bool constantTimeEquals(const unsigned char* a, size_t a_len, const unsigned char* b, size_t b_len) noexcept;

private:
    int securityParam;
    PublicKey currentPk;
    std::mt19937_64 rng;
    std::vector<std::vector<mpz_class>> S_matrix;

    mpz_class getRandomExponent();
    
    void generateCommitments(
        const PublicKey& pk,
        const std::vector<int>& permutation,
        ShuffleProof& proof);

    void computeResponses(
        const PublicKey& pk,
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
        const mpz_class& challenge) const;

    static void hashMpzToDigest(EVP_MD_CTX* ctx, const mpz_class& value) noexcept;
    [[nodiscard]] static bool isValidPublicKey(const PublicKey& pk) noexcept;
    [[nodiscard]] static bool isSafePrime(const mpz_class& p, const mpz_class& q) noexcept;
};

[[nodiscard]] size_t estimateProofSize(const ShuffleProof& proof) noexcept;
[[nodiscard]] size_t estimateCiphertextSize(const Ciphertext& ct) noexcept;

} // namespace BayerGroth

#endif // BAYER_GROTH_SHUFFLE_H

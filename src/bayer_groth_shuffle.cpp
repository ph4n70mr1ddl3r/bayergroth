#include "bayer_groth_shuffle.h"
#include "crypto_utils.h"
#include <sstream>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <cstring>
#include <ctime>
#include <cstddef>
#include <numeric>

void getRandomBytesFromDevice(unsigned char* buffer, size_t size) {
    int result = RAND_bytes(buffer, size);

    if (result != 1) {
        FILE* f = fopen("/dev/urandom", "rb");
        if (f) {
            size_t read_count = fread(buffer, 1, size, f);
            fclose(f);
            if (read_count != size) {
                throw std::runtime_error("Failed to read sufficient random bytes from /dev/urandom");
            }
        } else {
            throw std::runtime_error("Failed to read from /dev/urandom and OpenSSL RAND_bytes failed");
        }
    }
}

std::vector<unsigned char> getRandomBytesFromDevice(size_t size) {
    std::vector<unsigned char> buffer(size);
    getRandomBytesFromDevice(buffer.data(), size);
    return buffer;
}

namespace BayerGroth {

struct EvpMdCtx {
    EVP_MD_CTX* ctx;
    EvpMdCtx() : ctx(EVP_MD_CTX_new()) {
        if (!ctx) throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    ~EvpMdCtx() {
        if (ctx) EVP_MD_CTX_free(ctx);
    }
    EvpMdCtx(const EvpMdCtx&) = delete;
    EvpMdCtx& operator=(const EvpMdCtx&) = delete;
    EVP_MD_CTX* get() noexcept { return ctx; }
    const EVP_MD_CTX* get() const noexcept { return ctx; }
};

static const mpz_class ZERO(0);
static const mpz_class ONE(1);
static const mpz_class TWO(2);
static constexpr int PRIME_ITERATIONS = 100;
static constexpr size_t MAX_RANDOM_RETRY = 100;
static constexpr size_t MIN_SECURE_BYTES = 32;

struct GmpRandState {
    gmp_randstate_t state;
    GmpRandState() {
        gmp_randinit_default(state);
    }
    ~GmpRandState() {
        gmp_randclear(state);
    }
    GmpRandState(const GmpRandState&) = delete;
    GmpRandState& operator=(const GmpRandState&) = delete;
};

static void getSecureRandomBytes(unsigned char* buffer, size_t size) {
    getRandomBytesFromDevice(buffer, size);
}

BayerGrothShuffle::BayerGrothShuffle(int securityParam_)
    : securityParam(std::max(securityParam_, 256)) {
    std::vector<unsigned char> seed_bytes(32);
    getSecureRandomBytes(seed_bytes.data(), 32);
    std::seed_seq seed_seq(seed_bytes.begin(), seed_bytes.end());
    rng.seed(seed_seq);
}

BayerGrothShuffle::~BayerGrothShuffle() noexcept {
    for (auto& row : S_matrix) {
        for (auto& val : row) {
            OPENSSL_cleanse(val.get_mpz_t(), sizeof(mpz_t));
        }
    }
    S_matrix.clear();
    OPENSSL_cleanse(currentPk.g.get_mpz_t(), sizeof(mpz_t));
    OPENSSL_cleanse(currentPk.h.get_mpz_t(), sizeof(mpz_t));
    OPENSSL_cleanse(currentPk.q.get_mpz_t(), sizeof(mpz_t));
    OPENSSL_cleanse(currentPk.p.get_mpz_t(), sizeof(mpz_t));
}

void BayerGrothShuffle::setRandomGenerator(std::mt19937_64 rng_) {
    rng = rng_;
}

void BayerGrothShuffle::hashMpzToDigest(EVP_MD_CTX* ctx, const mpz_class& value) noexcept {
    size_t size = (mpz_sizeinbase(value.get_mpz_t(), 2) + 7) / 8;
    std::vector<unsigned char> bytes(size);
    mpz_export(bytes.data(), nullptr, 1, 1, 0, 0, value.get_mpz_t());
    EVP_DigestUpdate(ctx, bytes.data(), bytes.size());
}

bool BayerGrothShuffle::isSafePrime(const mpz_class& p, const mpz_class& q) noexcept {
    if (q <= ONE) return false;
    mpz_class two_q_plus_one;
    mpz_mul_ui(two_q_plus_one.get_mpz_t(), q.get_mpz_t(), 2);
    mpz_add_ui(two_q_plus_one.get_mpz_t(), two_q_plus_one.get_mpz_t(), 1);
    if (p != two_q_plus_one) return false;
    return mpz_probab_prime_p(q.get_mpz_t(), PRIME_ITERATIONS) != 0;
}

bool BayerGrothShuffle::isValidPublicKey(const PublicKey& pk) noexcept {
    if (pk.p <= 0 || pk.q <= 0 || pk.g <= 0 || pk.h <= 0) return false;
    if (pk.g <= ONE || pk.g >= pk.p) return false;
    if (pk.h <= ONE || pk.h >= pk.p) return false;
    if (pk.g == pk.h) return false;

    mpz_class p_minus_one;
    mpz_sub_ui(p_minus_one.get_mpz_t(), pk.p.get_mpz_t(), 1);
    mpz_class p_minus_one_div_q;
    mpz_tdiv_q(p_minus_one_div_q.get_mpz_t(), p_minus_one.get_mpz_t(), pk.q.get_mpz_t());
    if (mpz_cmp_ui(p_minus_one_div_q.get_mpz_t(), 2) != 0) return false;

    mpz_class g_q;
    mpz_powm(g_q.get_mpz_t(), pk.g.get_mpz_t(), pk.q.get_mpz_t(), pk.p.get_mpz_t());
    if (g_q != ONE) return false;

    mpz_class h_q;
    mpz_powm(h_q.get_mpz_t(), pk.h.get_mpz_t(), pk.q.get_mpz_t(), pk.p.get_mpz_t());
    if (h_q != ONE) return false;

    if (!isSafePrime(pk.p, pk.q)) return false;

    return true;
}

static std::vector<unsigned char> getRandomBytes(size_t byte_count) {
    return getRandomBytesFromDevice(byte_count);
}

mpz_class BayerGrothShuffle::getSecureRandom(const mpz_class& limit) {
    if (limit <= ONE) {
        return ZERO;
    }

    size_t limit_bits = mpz_sizeinbase(limit.get_mpz_t(), 2);
    size_t byte_count = (limit_bits + 7) / 8;
    if (byte_count < 32) byte_count = 32;

    mpz_class limit_minus_one = limit - ONE;
    mpz_class max_valid = 0;
    for (size_t i = 0; i < byte_count; ++i) {
        max_valid = max_valid * 256;
    }
    max_valid = max_valid - (max_valid % limit);

    for (size_t retry = 0; retry < MAX_RANDOM_RETRY; ++retry) {
        std::vector<unsigned char> random_bytes = getRandomBytes(byte_count);

        mpz_class result_mpz = ZERO;
        for (size_t i = 0; i < byte_count; ++i) {
            result_mpz = result_mpz * 256 + random_bytes[i];
        }

        if (result_mpz < max_valid) {
            return result_mpz % limit;
        }
    }

    std::vector<unsigned char> random_bytes = getRandomBytes(byte_count);
    mpz_class result_mpz = ZERO;
    for (size_t i = 0; i < byte_count; ++i) {
        result_mpz = result_mpz * 256 + random_bytes[i];
    }
    return result_mpz % limit;
}

mpz_class BayerGrothShuffle::generateRandomNumber(const mpz_class& limit) {
    return getSecureRandom(limit);
}

mpz_class BayerGrothShuffle::getRandomExponent() {
    return getSecureRandom(currentPk.q);
}

std::vector<int> BayerGrothShuffle::generatePermutation(size_t n, std::mt19937_64& rng) {
    std::vector<int> perm(n);
    std::iota(perm.begin(), perm.end(), 0);
    std::shuffle(perm.begin(), perm.end(), rng);
    return perm;
}

KeyPair BayerGrothShuffle::generateKeyPair() {
    KeyPair keyPair;

    GmpRandState randState;

    std::vector<unsigned char> seed_bytes(64);
    getSecureRandomBytes(seed_bytes.data(), 64);

    mpz_class seed_mpz = ZERO;
    for (size_t i = 0; i < 64; ++i) {
        seed_mpz = seed_mpz * 256 + seed_bytes[i];
    }
    gmp_randseed(randState.state, seed_mpz.get_mpz_t());

    size_t p_bits = securityParam;
    size_t q_bits = p_bits - 1;

    mpz_class p, q;

    int prime_attempts = 0;
    bool found_safe_prime = false;

    while (!found_safe_prime && prime_attempts < 10000) {
        mpz_urandomb(q.get_mpz_t(), randState.state, q_bits);

        do {
            mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());
        } while (mpz_probab_prime_p(q.get_mpz_t(), PRIME_ITERATIONS) == 0);

        mpz_mul_ui(p.get_mpz_t(), q.get_mpz_t(), 2);
        mpz_add_ui(p.get_mpz_t(), p.get_mpz_t(), 1);

        if (mpz_probab_prime_p(p.get_mpz_t(), PRIME_ITERATIONS) != 0) {
            found_safe_prime = true;
            break;
        }

        ++prime_attempts;
    }

    if (!found_safe_prime) {
        throw std::runtime_error("Failed to generate safe prime");
    }

    keyPair.pk.q = q;
    keyPair.pk.p = p;

    mpz_class g_candidate;
    mpz_class g_power;
    int attempts = 0;
    do {
        mpz_urandomb(g_candidate.get_mpz_t(), randState.state, p_bits);
        g_candidate = modAdd(g_candidate, TWO, keyPair.pk.p);

        mpz_powm(g_power.get_mpz_t(), g_candidate.get_mpz_t(),
                 keyPair.pk.q.get_mpz_t(), keyPair.pk.p.get_mpz_t());
        attempts++;
        if (attempts > 100) {
            g_candidate = TWO;
            mpz_powm(g_power.get_mpz_t(), g_candidate.get_mpz_t(),
                     keyPair.pk.q.get_mpz_t(), keyPair.pk.p.get_mpz_t());
            break;
        }
    } while (g_power != ONE);

    keyPair.pk.g = g_candidate;

    mpz_urandomb(keyPair.sk.get_mpz_t(), randState.state, q_bits);
    keyPair.sk = modAdd(keyPair.sk, TWO, keyPair.pk.q);

    mpz_powm(keyPair.pk.h.get_mpz_t(), keyPair.pk.g.get_mpz_t(),
             keyPair.sk.get_mpz_t(), keyPair.pk.p.get_mpz_t());

    if (!isValidPublicKey(keyPair.pk)) {
        throw std::runtime_error("Generated invalid public key");
    }

    currentPk = keyPair.pk;

    return keyPair;
}

Ciphertext BayerGrothShuffle::encrypt(const PublicKey& pk, const mpz_class& message) {
    if (!isValidPublicKey(pk)) {
        throw std::invalid_argument("Invalid public key parameters");
    }
    if (message < ONE || message >= pk.p) {
        throw std::invalid_argument("Message must be in range [1, p)");
    }

    mpz_class r = getSecureRandom(pk.q);

    Ciphertext ct;
    mpz_powm(ct.a.get_mpz_t(), pk.g.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
    mpz_powm(ct.b.get_mpz_t(), pk.h.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
    ct.b = modMul(message, ct.b, pk.p);

    return ct;
}

Ciphertext BayerGrothShuffle::reEncrypt(const PublicKey& pk, const Ciphertext& ct, const mpz_class& r) {
    Ciphertext result;

    mpz_powm(result.a.get_mpz_t(), pk.g.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
    mpz_powm(result.b.get_mpz_t(), pk.h.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());

    result.a = modMul(ct.a, result.a, pk.p);
    result.b = modMul(ct.b, result.b, pk.p);

    return result;
}

mpz_class BayerGrothShuffle::decrypt(const PublicKey& pk, const mpz_class& sk, const Ciphertext& ct) {
    mpz_class a_sk;
    mpz_powm(a_sk.get_mpz_t(), ct.a.get_mpz_t(), sk.get_mpz_t(), pk.p.get_mpz_t());
    mpz_class a_sk_inv;
    mpz_invert(a_sk_inv.get_mpz_t(), a_sk.get_mpz_t(), pk.p.get_mpz_t());
    mpz_class message = modMul(ct.b, a_sk_inv, pk.p);
    return message;
}

bool BayerGrothShuffle::constantTimeEquals(const mpz_class& a, const mpz_class& b) noexcept {
    size_t a_size = mpz_sizeinbase(a.get_mpz_t(), 2);
    size_t b_size = mpz_sizeinbase(b.get_mpz_t(), 2);

    size_t a_bytes = (a_size + 7) / 8;
    size_t b_bytes = (b_size + 7) / 8;

    size_t max_bytes = std::max(a_bytes, b_bytes);
    if (max_bytes < 32) max_bytes = 32;

    std::vector<unsigned char> a_padded(max_bytes, 0);
    std::vector<unsigned char> b_padded(max_bytes, 0);

    mpz_export(a_padded.data(), nullptr, 1, 1, 0, 0, a.get_mpz_t());
    mpz_export(b_padded.data(), nullptr, 1, 1, 0, 0, b.get_mpz_t());

    unsigned char len_diff = static_cast<unsigned char>(a_bytes != b_bytes);
    unsigned char result = 0;
    result |= len_diff;

    for (size_t i = 0; i < max_bytes; ++i) {
        result |= static_cast<unsigned char>(a_padded[i] ^ b_padded[i]);
    }

    return result == 0;
}

bool BayerGrothShuffle::constantTimeEquals(const unsigned char* a, size_t a_len, const unsigned char* b, size_t b_len) noexcept {
    if (a_len != b_len) {
        return false;
    }
    return CRYPTO_memcmp(a, b, a_len) == 0;
}

static bool isValidElement(const mpz_class& val, const mpz_class& mod) {
    return val >= ONE && val < mod;
}

void BayerGrothShuffle::generateCommitments(
    const PublicKey& pk,
    const std::vector<int>& permutation,
    ShuffleProof& proof) {

    size_t n = permutation.size();

    proof.A.resize(n, std::vector<mpz_class>(n));
    proof.B.resize(n, std::vector<mpz_class>(n));
    proof.D.resize(n, std::vector<mpz_class>(n));
    S_matrix.resize(n, std::vector<mpz_class>(n));

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            mpz_class s = getRandomExponent();
            S_matrix[i][j] = s;
            mpz_powm(proof.A[i][j].get_mpz_t(), pk.g.get_mpz_t(), s.get_mpz_t(), pk.p.get_mpz_t());
            mpz_powm(proof.B[i][j].get_mpz_t(), pk.h.get_mpz_t(), s.get_mpz_t(), pk.p.get_mpz_t());

            mpz_class alpha_ij = getRandomExponent();
            mpz_class beta_ij = getRandomExponent();
            mpz_class d_ij = modExp(pk.g, alpha_ij, pk.p);
            d_ij = modMul(d_ij, modExp(pk.h, beta_ij, pk.p), pk.p);
            proof.D[i][j] = d_ij;
        }
    }
}

mpz_class BayerGrothShuffle::computeChallenge(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof) const {

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EvpMdCtx evpCtx;
    EVP_DigestInit_ex(evpCtx.get(), EVP_sha256(), nullptr);

    unsigned char domain_sep = 0x01;
    EVP_DigestUpdate(evpCtx.get(), &domain_sep, sizeof(domain_sep));

    size_t n = proof.A.size();
    unsigned char n_bytes[sizeof(size_t)];
    std::memcpy(n_bytes, &n, sizeof(size_t));
    EVP_DigestUpdate(evpCtx.get(), n_bytes, sizeof(n_bytes));

    hashMpzToDigest(evpCtx.get(), pk.g);
    hashMpzToDigest(evpCtx.get(), pk.h);
    hashMpzToDigest(evpCtx.get(), pk.q);
    hashMpzToDigest(evpCtx.get(), pk.p);

    for (size_t i = 0; i < proof.A.size(); ++i) {
        for (size_t j = 0; j < proof.A[i].size(); ++j) {
            hashMpzToDigest(evpCtx.get(), proof.A[i][j]);
        }
    }

    for (size_t i = 0; i < proof.B.size(); ++i) {
        for (size_t j = 0; j < proof.B[i].size(); ++j) {
            hashMpzToDigest(evpCtx.get(), proof.B[i][j]);
        }
    }

    for (size_t i = 0; i < proof.D.size(); ++i) {
        for (size_t j = 0; j < proof.D[i].size(); ++j) {
            hashMpzToDigest(evpCtx.get(), proof.D[i][j]);
        }
    }

    size_t input_size = input.size();
    unsigned char input_n_bytes[sizeof(size_t)];
    std::memcpy(input_n_bytes, &input_size, sizeof(size_t));
    EVP_DigestUpdate(evpCtx.get(), input_n_bytes, sizeof(input_n_bytes));

    for (const auto& ct : input) {
        hashMpzToDigest(evpCtx.get(), ct.a);
        hashMpzToDigest(evpCtx.get(), ct.b);
    }

    size_t output_size = output.size();
    unsigned char output_n_bytes[sizeof(size_t)];
    std::memcpy(output_n_bytes, &output_size, sizeof(size_t));
    EVP_DigestUpdate(evpCtx.get(), output_n_bytes, sizeof(output_n_bytes));

    for (const auto& ct : output) {
        hashMpzToDigest(evpCtx.get(), ct.a);
        hashMpzToDigest(evpCtx.get(), ct.b);
    }

    EVP_DigestFinal_ex(evpCtx.get(), hash, &hash_len);

    mpz_class challenge = ZERO;
    for (unsigned int i = 0; i < hash_len; ++i) {
        challenge = challenge * 256 + hash[i];
    }

    return challenge % pk.q;
}

void BayerGrothShuffle::computeResponses(
    const PublicKey& pk,
    const std::vector<mpz_class>& inputRand,
    const std::vector<mpz_class>& outputRand,
    const std::vector<int>& permutation,
    const mpz_class& challenge,
    ShuffleProof& proof) {

    size_t n = permutation.size();

    proof.z1.resize(n);
    proof.z2.resize(n);
    proof.z3.resize(n);
    proof.z4.resize(n);
    proof.z5.resize(n);
    proof.z6.resize(n);
    proof.z7.resize(n);
    proof.z8.resize(n);
    proof.z9 = ZERO;
    proof.z10 = ZERO;

    std::vector<int> inv_perm(n);
    for (size_t j = 0; j < n; ++j) {
        inv_perm[permutation[j]] = j;
    }

    std::vector<mpz_class> row_sum(n, ZERO);
    std::vector<mpz_class> col_sum(n, ZERO);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            row_sum[i] = modAdd(row_sum[i], S_matrix[i][j], pk.q);
            col_sum[j] = modAdd(col_sum[j], S_matrix[i][j], pk.q);
        }
    }

    for (size_t i = 0; i < n; ++i) {
        mpz_class term = modMul(inputRand[permutation[i]], challenge, pk.q);
        proof.z1[i] = modAdd(outputRand[i], term, pk.q);
    }

    for (size_t i = 0; i < n; ++i) {
        mpz_class term = modMul(row_sum[i], challenge, pk.q);
        proof.z2[i] = modAdd(inputRand[i], term, pk.q);
    }

    for (size_t i = 0; i < n; ++i) {
        proof.z3[i] = S_matrix[i][permutation[i]];
    }

    for (size_t i = 0; i < n; ++i) {
        proof.z4[i] = S_matrix[inv_perm[i]][i];
    }

    for (size_t i = 0; i < n; ++i) {
        mpz_class term_row = modMul(row_sum[i], challenge, pk.q);
        mpz_class term_col = modMul(col_sum[i], challenge, pk.q);

        proof.z5[i] = term_row;
        proof.z6[i] = term_row;
        proof.z7[i] = term_col;
        proof.z8[i] = term_col;
    }

    mpz_class sum_all_s = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_all_s = modAdd(sum_all_s, row_sum[i], pk.q);
    }

    mpz_class sum_s_c = modMul(sum_all_s, challenge, pk.q);

    proof.z9 = sum_s_c;
    proof.z10 = sum_s_c;

    mpz_class prod_d = ONE;
    for (size_t i = 0; i < n; ++i) {
        prod_d = modMul(prod_d, proof.D[i][permutation[i]], pk.p);
    }
    proof.d = prod_d;
}

std::vector<Ciphertext> BayerGrothShuffle::shuffle(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<mpz_class>& randomness,
    const std::vector<int>& permutation,
    ShuffleProof& proof) {

    if (!isValidPublicKey(pk)) {
        throw std::invalid_argument("Invalid public key");
    }

    currentPk = pk;
    size_t n = input.size();

    if (n == 0) {
        throw std::invalid_argument("Input array cannot be empty");
    }
    if (randomness.size() != n) {
        throw std::invalid_argument("Randomness size must match input size");
    }
    if (permutation.size() != n) {
        throw std::invalid_argument("Permutation size must match input size");
    }

    for (auto& row : S_matrix) {
        for (auto& val : row) {
            OPENSSL_cleanse(val.get_mpz_t(), sizeof(mpz_t));
        }
    }
    S_matrix.clear();

    std::vector<int> count(n, 0);
    for (int p : permutation) {
        if (p < 0 || p >= static_cast<int>(n)) {
            throw std::invalid_argument("Invalid permutation value");
        }
        count[p]++;
    }
    for (size_t i = 0; i < n; ++i) {
        if (count[i] != 1) {
            throw std::invalid_argument("Invalid permutation: must be a bijection");
        }
    }

    proof.permutation = permutation;

    std::vector<mpz_class> outputRand(n);
    for (size_t i = 0; i < n; ++i) {
        outputRand[i] = getRandomExponent();
    }

    std::vector<Ciphertext> reencrypted(n);
    for (size_t i = 0; i < n; ++i) {
        reencrypted[i] = reEncrypt(pk, input[i], randomness[i]);
    }

    std::vector<Ciphertext> output(n);
    for (size_t i = 0; i < n; ++i) {
        output[i] = reencrypted[permutation[i]];
        mpz_class g_new = modExp(pk.g, outputRand[i], pk.p);
        mpz_class h_new = modExp(pk.h, outputRand[i], pk.p);
        output[i].a = modMul(output[i].a, g_new, pk.p);
        output[i].b = modMul(output[i].b, h_new, pk.p);
    }

    generateCommitments(pk, permutation, proof);
    mpz_class challenge = computeChallenge(pk, input, output, proof);

    mpz_class sum_output_rand = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_output_rand = modAdd(sum_output_rand, outputRand[i], pk.q);
    }
    mpz_class sum_input_rand = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_input_rand = modAdd(sum_input_rand, randomness[i], pk.q);
    }
    mpz_class expected_sum_z1 = modAdd(sum_output_rand, modMul(challenge, sum_input_rand, pk.q), pk.q);

    computeResponses(pk, randomness, outputRand, permutation, challenge, proof);

    mpz_class sum_other_z1 = ZERO;
    for (size_t i = 1; i < n; ++i) {
        sum_other_z1 = modAdd(sum_other_z1, proof.z1[i], pk.q);
    }
    proof.z1[0] = modSub(expected_sum_z1, sum_other_z1, pk.q);

    proof.t = modExp(pk.g, expected_sum_z1, pk.p);
    proof.u = modExp(pk.h, expected_sum_z1, pk.p);

    for (auto& row : S_matrix) {
        for (auto& val : row) {
            OPENSSL_cleanse(val.get_mpz_t(), sizeof(mpz_t));
        }
    }
    S_matrix.clear();

    return output;
}

bool BayerGrothShuffle::verifyEquations(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof,
    const mpz_class& challenge) const {

    size_t n = input.size();

    if (n != proof.A.size() || n != proof.B.size() || n != proof.D.size()) {
        return false;
    }
    for (size_t i = 0; i < n; ++i) {
        if (proof.A[i].size() != n || proof.B[i].size() != n || proof.D[i].size() != n) {
            return false;
        }
    }

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            if (!isValidElement(proof.A[i][j], pk.p) ||
                !isValidElement(proof.B[i][j], pk.p) ||
                !isValidElement(proof.D[i][j], pk.p)) {
                return false;
            }
        }
    }

    if (proof.z1.size() != n || proof.z2.size() != n ||
        proof.z3.size() != n || proof.z4.size() != n ||
        proof.z5.size() != n || proof.z6.size() != n ||
        proof.z7.size() != n || proof.z8.size() != n) {
        return false;
    }

    for (size_t i = 0; i < n; ++i) {
        if (!isValidElement(proof.z1[i], pk.q) ||
            !isValidElement(proof.z2[i], pk.q) ||
            !isValidElement(proof.z3[i], pk.q) ||
            !isValidElement(proof.z4[i], pk.q) ||
            !isValidElement(proof.z5[i], pk.q) ||
            !isValidElement(proof.z6[i], pk.q) ||
            !isValidElement(proof.z7[i], pk.q) ||
            !isValidElement(proof.z8[i], pk.q)) {
            return false;
        }
    }

    if (!isValidElement(proof.z9, pk.q) || !isValidElement(proof.z10, pk.q) ||
        !isValidElement(proof.t, pk.p) || !isValidElement(proof.u, pk.p) ||
        !isValidElement(proof.d, pk.p)) {
        return false;
    }

    mpz_class sum_z1 = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_z1 = modAdd(sum_z1, proof.z1[i], pk.q);
    }

    mpz_class g_sum_z1 = modExp(pk.g, sum_z1, pk.p);
    if (!constantTimeEquals(g_sum_z1, proof.t)) {
        return false;
    }

    mpz_class h_sum_z1 = modExp(pk.h, sum_z1, pk.p);
    if (!constantTimeEquals(h_sum_z1, proof.u)) {
        return false;
    }

    std::vector<int> inv_perm(n);
    for (size_t j = 0; j < n; ++j) {
        inv_perm[proof.permutation[j]] = j;
    }

    for (size_t i = 0; i < n; ++i) {
        mpz_class g_z3 = modExp(pk.g, proof.z3[i], pk.p);
        if (!constantTimeEquals(g_z3, proof.A[i][proof.permutation[i]])) {
            return false;
        }

        mpz_class g_z4 = modExp(pk.g, proof.z4[i], pk.p);
        if (!constantTimeEquals(g_z4, proof.A[inv_perm[i]][i])) {
            return false;
        }
    }

    for (size_t i = 0; i < n; ++i) {
        mpz_class prod_A_row_c = ONE;
        mpz_class prod_B_row_c = ONE;
        for (size_t j = 0; j < n; ++j) {
            mpz_class A_ij_c = modExp(proof.A[i][j], challenge, pk.p);
            mpz_class B_ij_c = modExp(proof.B[i][j], challenge, pk.p);
            prod_A_row_c = modMul(prod_A_row_c, A_ij_c, pk.p);
            prod_B_row_c = modMul(prod_B_row_c, B_ij_c, pk.p);
        }

        mpz_class g_z5 = modExp(pk.g, proof.z5[i], pk.p);
        if (!constantTimeEquals(g_z5, prod_A_row_c)) {
            return false;
        }

        mpz_class h_z6 = modExp(pk.h, proof.z6[i], pk.p);
        if (!constantTimeEquals(h_z6, prod_B_row_c)) {
            return false;
        }
    }

    for (size_t i = 0; i < n; ++i) {
        mpz_class prod_A_col_c = ONE;
        mpz_class prod_B_col_c = ONE;
        for (size_t j = 0; j < n; ++j) {
            mpz_class A_ji_c = modExp(proof.A[j][i], challenge, pk.p);
            mpz_class B_ji_c = modExp(proof.B[j][i], challenge, pk.p);
            prod_A_col_c = modMul(prod_A_col_c, A_ji_c, pk.p);
            prod_B_col_c = modMul(prod_B_col_c, B_ji_c, pk.p);
        }

        mpz_class g_z7 = modExp(pk.g, proof.z7[i], pk.p);
        if (!constantTimeEquals(g_z7, prod_A_col_c)) {
            return false;
        }

        mpz_class h_z8 = modExp(pk.h, proof.z8[i], pk.p);
        if (!constantTimeEquals(h_z8, prod_B_col_c)) {
            return false;
        }
    }

    mpz_class expected_d = ONE;
    for (size_t i = 0; i < n; ++i) {
        expected_d = modMul(expected_d, proof.D[i][proof.permutation[i]], pk.p);
    }
    if (!constantTimeEquals(proof.d, expected_d)) {
        return false;
    }

    return true;
}

bool BayerGrothShuffle::verify(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof) const {

    if (!isValidPublicKey(pk)) {
        return false;
    }

    if (input.size() != output.size()) {
        return false;
    }

    if (input.empty()) {
        return true;
    }

    if (proof.A.empty() || proof.B.empty() || proof.D.empty() ||
        proof.z1.empty() || proof.z5.empty() || proof.permutation.empty()) {
        return false;
    }

    mpz_class challenge = computeChallenge(pk, input, output, proof);

    return verifyEquations(pk, input, output, proof, challenge);
}

mpz_class BayerGrothShuffle::modExp(const mpz_class& base, const mpz_class& exp, const mpz_class& mod) {
    if (exp < ZERO) {
        throw std::invalid_argument("Exponent must be non-negative");
    }
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return result;
}

mpz_class BayerGrothShuffle::modInv(const mpz_class& a, const mpz_class& mod) {
    mpz_class result;
    mpz_invert(result.get_mpz_t(), a.get_mpz_t(), mod.get_mpz_t());
    return result;
}

mpz_class BayerGrothShuffle::modAdd(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    mpz_class result = a + b;
    result %= mod;
    if (result < 0) result += mod;
    return result;
}

mpz_class BayerGrothShuffle::modSub(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    mpz_class result = a - b;
    result %= mod;
    if (result < 0) result += mod;
    return result;
}

mpz_class BayerGrothShuffle::modMul(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    mpz_class result = a * b;
    result %= mod;
    return result;
}

mpz_class BayerGrothShuffle::modDiv(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    if (b == ZERO) {
        throw std::invalid_argument("Division by zero in modular arithmetic");
    }
    mpz_class b_inv;
    if (mpz_invert(b_inv.get_mpz_t(), b.get_mpz_t(), mod.get_mpz_t()) == 0) {
        return ZERO;
    }
    return modMul(a, b_inv, mod);
}

size_t estimateProofSize(const ShuffleProof& proof) noexcept {
    size_t size = 0;
    for (const auto& row : proof.A) {
        for (const auto& val : row) size += val.get_str().size();
    }
    for (const auto& row : proof.B) {
        for (const auto& val : row) size += val.get_str().size();
    }
    for (const auto& row : proof.D) {
        for (const auto& val : row) size += val.get_str().size();
    }
    for (const auto& val : proof.z1) size += val.get_str().size();
    for (const auto& val : proof.z2) size += val.get_str().size();
    for (const auto& val : proof.z3) size += val.get_str().size();
    for (const auto& val : proof.z4) size += val.get_str().size();
    for (const auto& val : proof.z5) size += val.get_str().size();
    for (const auto& val : proof.z6) size += val.get_str().size();
    for (const auto& val : proof.z7) size += val.get_str().size();
    for (const auto& val : proof.z8) size += val.get_str().size();
    size += proof.z9.get_str().size();
    size += proof.z10.get_str().size();
    size += proof.t.get_str().size();
    size += proof.u.get_str().size();
    size += proof.d.get_str().size();
    return size;
}

size_t estimateCiphertextSize(const Ciphertext& ct) noexcept {
    return ct.a.get_str().size() + ct.b.get_str().size();
}

} // namespace BayerGroth

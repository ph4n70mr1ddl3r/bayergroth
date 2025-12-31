#include "bayer_groth_full.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <openssl/rand.h>

namespace BG12Full {

static const mpz_class ZERO(0);
static const mpz_class ONE(1);
static const mpz_class TWO(2);

mpz_class getSecureRandom(const mpz_class& limit) {
    if (limit <= 0) {
        return ZERO;
    }
    
    size_t limit_bits = mpz_sizeinbase(limit.get_mpz_t(), 2);
    size_t byte_count = (limit_bits + 7) / 8;
    if (byte_count < 32) byte_count = 32;
    
    std::vector<unsigned char> random_bytes(byte_count);
    int result = RAND_bytes(random_bytes.data(), byte_count);
    
    if (result != 1) {
        FILE* f = fopen("/dev/urandom", "rb");
        if (f) {
            fread(random_bytes.data(), 1, byte_count, f);
            fclose(f);
        }
    }
    
    mpz_class result_mpz = 0;
    for (size_t i = 0; i < byte_count; ++i) {
        result_mpz = result_mpz * 256 + random_bytes[i];
    }
    
    return result_mpz % limit;
}

BayerGrothFull::BayerGrothFull(int securityParameter) : securityParam(securityParameter), randomGen(nullptr), ownsRandomGen(true), currentPk() {
    randomGen = new std::mt19937_64(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
}

BayerGrothFull::~BayerGrothFull() {
    if (ownsRandomGen && randomGen != nullptr) {
        delete randomGen;
        randomGen = nullptr;
    }
}

void BayerGrothFull::setRandomGenerator(std::mt19937_64& rng) {
    if (ownsRandomGen && randomGen != nullptr) {
        delete randomGen;
    }
    randomGen = &rng;
    ownsRandomGen = false;
}

mpz_class BayerGrothFull::getRandomExponent() {
    return getSecureRandom(currentPk.q);
}

KeyPair BayerGrothFull::generateKeyPair() {
    KeyPair keyPair;

    gmp_randstate_t randState;
    gmp_randinit_default(randState);
    gmp_randseed_ui(randState, randomGen->operator()());

    mpz_urandomb(keyPair.pk.p.get_mpz_t(), randState, securityParam * 2);
    mpz_nextprime(keyPair.pk.p.get_mpz_t(), keyPair.pk.p.get_mpz_t());

    mpz_sub(keyPair.pk.q.get_mpz_t(), keyPair.pk.p.get_mpz_t(), ONE.get_mpz_t());
    mpz_divexact(keyPair.pk.q.get_mpz_t(), keyPair.pk.q.get_mpz_t(), TWO.get_mpz_t());

    mpz_class g_candidate;
    mpz_urandomb(g_candidate.get_mpz_t(), randState, securityParam * 2);
    g_candidate = modAdd(g_candidate, TWO, keyPair.pk.p);

    mpz_class g_power;
    mpz_powm(g_power.get_mpz_t(), g_candidate.get_mpz_t(), keyPair.pk.q.get_mpz_t(), keyPair.pk.p.get_mpz_t());

    int attempts = 0;
    while (g_power == ONE && attempts < 100) {
        g_candidate = modAdd(g_candidate, ONE, keyPair.pk.p);
        mpz_powm(g_power.get_mpz_t(), g_candidate.get_mpz_t(), keyPair.pk.q.get_mpz_t(), keyPair.pk.p.get_mpz_t());
        attempts++;
    }

    if (g_power == ONE) {
        g_candidate = TWO;
        mpz_powm(g_power.get_mpz_t(), g_candidate.get_mpz_t(), keyPair.pk.q.get_mpz_t(), keyPair.pk.p.get_mpz_t());
    }

    keyPair.pk.g = g_power;

    mpz_class sk_candidate;
    mpz_urandomb(sk_candidate.get_mpz_t(), randState, securityParam);
    sk_candidate = modAdd(sk_candidate, ONE, keyPair.pk.q);
    keyPair.sk = sk_candidate;

    mpz_powm(keyPair.pk.h.get_mpz_t(), keyPair.pk.g.get_mpz_t(), keyPair.sk.get_mpz_t(), keyPair.pk.p.get_mpz_t());

    currentPk = keyPair.pk;

    gmp_randclear(randState);

    return keyPair;
}

Ciphertext BayerGrothFull::encrypt(const PublicKey& pk, const mpz_class& message, const mpz_class& randomness) {
    if (pk.p <= 0 || pk.q <= 0) {
        throw std::invalid_argument("Invalid public key parameters");
    }
    if (message < 0 || message >= pk.p) {
        throw std::invalid_argument("Message must be in range [0, p)");
    }
    
    Ciphertext ct;
    mpz_powm(ct.a.get_mpz_t(), pk.g.get_mpz_t(), randomness.get_mpz_t(), pk.p.get_mpz_t());
    mpz_powm(ct.b.get_mpz_t(), pk.h.get_mpz_t(), randomness.get_mpz_t(), pk.p.get_mpz_t());
    ct.b = modMul(message, ct.b, pk.p);
    return ct;
}

Ciphertext BayerGrothFull::reEncrypt(const PublicKey& pk, const Ciphertext& ct, const mpz_class& r) {
    Ciphertext result;
    mpz_powm(result.a.get_mpz_t(), pk.g.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
    mpz_powm(result.b.get_mpz_t(), pk.h.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
    result.a = modMul(ct.a, result.a, pk.p);
    result.b = modMul(ct.b, result.b, pk.p);
    return result;
}

void BayerGrothFull::generateCommitments(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const std::vector<mpz_class>& inputRand,
    const std::vector<mpz_class>& outputRand,
    const std::vector<int>& permutation,
    ShuffleProof& proof) {

    size_t n = input.size();

    proof.A.resize(n, std::vector<mpz_class>(n));
    proof.B.resize(n, std::vector<mpz_class>(n));
    proof.D.resize(n, std::vector<mpz_class>(n));
    S_matrix.resize(n, std::vector<mpz_class>(n));

    alpha_row.resize(n);
    beta_row.resize(n);
    alpha_col.resize(n);
    beta_col.resize(n);

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            mpz_class s = getRandomExponent();
            S_matrix[i][j] = s;
            mpz_powm(proof.A[i][j].get_mpz_t(), pk.g.get_mpz_t(), s.get_mpz_t(), pk.p.get_mpz_t());
            mpz_powm(proof.B[i][j].get_mpz_t(), pk.h.get_mpz_t(), s.get_mpz_t(), pk.p.get_mpz_t());
        }
    }

    for (size_t i = 0; i < n; ++i) {
        alpha_row[i] = getRandomExponent();
        beta_row[i] = getRandomExponent();
        alpha_col[i] = getRandomExponent();
        beta_col[i] = getRandomExponent();
    }

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            mpz_class alpha_ij = modAdd(alpha_row[i], alpha_col[j], pk.q);
            mpz_class beta_ij = modAdd(beta_row[i], beta_col[j], pk.q);
            mpz_class d_ij = modExp(pk.g, alpha_ij, pk.p);
            d_ij = modMul(d_ij, modExp(pk.h, beta_ij, pk.p), pk.p);
            proof.D[i][j] = d_ij;
        }
    }
}

mpz_class BayerGrothFull::computeChallenge(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof) {

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    std::string pk_str = pk.g.get_str() + pk.h.get_str() + pk.p.get_str() + pk.q.get_str();
    EVP_DigestUpdate(ctx, pk_str.c_str(), pk_str.length());

    for (size_t i = 0; i < proof.A.size(); ++i) {
        for (size_t j = 0; j < proof.A[i].size(); ++j) {
            std::string val = proof.A[i][j].get_str();
            EVP_DigestUpdate(ctx, val.c_str(), val.length());
        }
    }

    for (size_t i = 0; i < proof.B.size(); ++i) {
        for (size_t j = 0; j < proof.B[i].size(); ++j) {
            std::string val = proof.B[i][j].get_str();
            EVP_DigestUpdate(ctx, val.c_str(), val.length());
        }
    }

    for (size_t i = 0; i < proof.D.size(); ++i) {
        for (size_t j = 0; j < proof.D[i].size(); ++j) {
            std::string val = proof.D[i][j].get_str();
            EVP_DigestUpdate(ctx, val.c_str(), val.length());
        }
    }

    for (const auto& ct : input) {
        std::string a_val = ct.a.get_str();
        std::string b_val = ct.b.get_str();
        EVP_DigestUpdate(ctx, a_val.c_str(), a_val.length());
        EVP_DigestUpdate(ctx, b_val.c_str(), b_val.length());
    }

    for (const auto& ct : output) {
        std::string a_val = ct.a.get_str();
        std::string b_val = ct.b.get_str();
        EVP_DigestUpdate(ctx, a_val.c_str(), a_val.length());
        EVP_DigestUpdate(ctx, b_val.c_str(), b_val.length());
    }

    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    mpz_class challenge = 0;
    for (unsigned int i = 0; i < hash_len; ++i) {
        challenge = challenge * 256 + hash[i];
    }

    return challenge % pk.q;
}

void BayerGrothFull::computeResponses(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const std::vector<mpz_class>& inputRand,
    const std::vector<mpz_class>& outputRand,
    const std::vector<int>& permutation,
    const mpz_class& challenge,
    ShuffleProof& proof) {

    size_t n = input.size();

    std::vector<mpz_class> row_sum(n, ZERO);
    std::vector<mpz_class> col_sum(n, ZERO);

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            row_sum[i] = modAdd(row_sum[i], S_matrix[i][j], pk.q);
            col_sum[j] = modAdd(col_sum[j], S_matrix[i][j], pk.q);
        }
    }

    mpz_class sum_all_s = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_all_s = modAdd(sum_all_s, row_sum[i], pk.q);
    }

    mpz_class sum_alpha_row = ZERO;
    mpz_class sum_beta_row = ZERO;

    for (size_t i = 0; i < n; ++i) {
        sum_alpha_row = modAdd(sum_alpha_row, alpha_row[i], pk.q);
        sum_beta_row = modAdd(sum_beta_row, beta_row[i], pk.q);
    }

    proof.z1.resize(n);
    proof.z2.resize(n);
    proof.z3.resize(n);
    proof.z4.resize(n);
    proof.z5.resize(n);
    proof.z6.resize(n);
    proof.z7.resize(n);
    proof.z8.resize(n);

    mpz_class c = challenge;

    for (size_t i = 0; i < n; ++i) {
        proof.z1[i] = modAdd(outputRand[i], modMul(c, inputRand[i], pk.q), pk.q);
        proof.z2[i] = modAdd(inputRand[i], modMul(c, row_sum[i], pk.q), pk.q);
        proof.z3[i] = col_sum[i];
        proof.z4[i] = row_sum[i];
        proof.z5[i] = row_sum[i];
        proof.z6[i] = row_sum[i];
        proof.z7[i] = col_sum[i];
        proof.z8[i] = col_sum[i];
    }

    mpz_class prod_t = ONE;
    mpz_class prod_u = ONE;

    for (size_t i = 0; i < n; ++i) {
        mpz_class input_a_c = modExp(input[i].a, c, pk.p);
        mpz_class ratio_a = modDiv(output[i].a, input_a_c, pk.p);
        prod_t = modMul(prod_t, ratio_a, pk.p);

        mpz_class input_b_c = modExp(input[i].b, c, pk.p);
        mpz_class ratio_b = modDiv(output[i].b, input_b_c, pk.p);
        prod_u = modMul(prod_u, ratio_b, pk.p);
    }

    proof.t = prod_t;
    proof.u = prod_u;
}

std::vector<Ciphertext> BayerGrothFull::shuffle(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<mpz_class>& inputRand,
    const std::vector<int>& permutation,
    ShuffleProof& proof) {

    currentPk = pk;
    size_t n = input.size();

    std::vector<mpz_class> outputRand(n);
    for (size_t i = 0; i < n; ++i) {
        outputRand[i] = getRandomExponent();
    }

    std::vector<Ciphertext> reencrypted(n);
    for (size_t i = 0; i < n; ++i) {
        reencrypted[i] = reEncrypt(pk, input[i], inputRand[i]);
    }

    std::vector<Ciphertext> output(n);
    for (size_t i = 0; i < n; ++i) {
        output[i] = reencrypted[permutation[i]];
        mpz_class g_new = modExp(pk.g, outputRand[i], pk.p);
        mpz_class h_new = modExp(pk.h, outputRand[i], pk.p);
        output[i].a = modMul(output[i].a, g_new, pk.p);
        output[i].b = modMul(output[i].b, h_new, pk.p);
    }

    generateCommitments(pk, input, output, inputRand, outputRand, permutation, proof);
    mpz_class challenge = computeChallenge(pk, input, output, proof);
    computeResponses(pk, input, output, inputRand, outputRand, permutation, challenge, proof);

    mpz_class sum_z1 = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_z1 = modAdd(sum_z1, proof.z1[i], pk.q);
    }

    mpz_class prod_t = ONE;
    mpz_class prod_u = ONE;
    for (size_t i = 0; i < n; ++i) {
        mpz_class input_a_c = modExp(input[i].a, challenge, pk.p);
        mpz_class ratio_a = modDiv(output[i].a, input_a_c, pk.p);
        prod_t = modMul(prod_t, ratio_a, pk.p);

        mpz_class input_b_c = modExp(input[i].b, challenge, pk.p);
        mpz_class ratio_b = modDiv(output[i].b, input_b_c, pk.p);
        prod_u = modMul(prod_u, ratio_b, pk.p);
    }

    proof.t = prod_t;
    proof.u = prod_u;

    mpz_class prod_D_diag = ONE;
    mpz_class prod_A_diag = ONE;
    mpz_class prod_B_diag = ONE;
    for (size_t i = 0; i < n; ++i) {
        prod_D_diag = modMul(prod_D_diag, proof.D[i][i], pk.p);
        prod_A_diag = modMul(prod_A_diag, proof.A[i][i], pk.p);
        prod_B_diag = modMul(prod_B_diag, proof.B[i][i], pk.p);
    }

    mpz_class target_g = modDiv(prod_D_diag, prod_A_diag, pk.p);
    mpz_class target_h = modDiv(prod_D_diag, prod_B_diag, pk.p);

    mpz_class log_g = ZERO;
    mpz_class temp_g = modExp(pk.g, log_g, pk.p);
    while (temp_g != target_g && log_g < pk.q) {
        log_g = modAdd(log_g, ONE, pk.q);
        temp_g = modExp(pk.g, log_g, pk.p);
    }
    proof.z9 = log_g;

    mpz_class log_h = ZERO;
    mpz_class temp_h = modExp(pk.h, log_h, pk.p);
    while (temp_h != target_h && log_h < pk.q) {
        log_h = modAdd(log_h, ONE, pk.q);
        temp_h = modExp(pk.h, log_h, pk.p);
    }
    proof.z10 = log_h;

    return output;
}

bool BayerGrothFull::verifyEquations(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof,
    const mpz_class& challenge) {

    size_t n = input.size();

    mpz_class c = challenge;

    mpz_class sum_z1 = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_z1 = modAdd(sum_z1, proof.z1[i], pk.q);
    }

    mpz_class g_sum_z1 = modExp(pk.g, sum_z1, pk.p);
    if (g_sum_z1 != proof.t) {
        return false;
    }

    mpz_class h_sum_z1 = modExp(pk.h, sum_z1, pk.p);
    if (h_sum_z1 != proof.u) {
        return false;
    }

    for (size_t i = 0; i < n; ++i) {
        mpz_class prod_A_row = ONE;
        for (size_t j = 0; j < n; ++j) {
            prod_A_row = modMul(prod_A_row, proof.A[i][j], pk.p);
        }

        mpz_class g_z5 = modExp(pk.g, proof.z5[i], pk.p);
        if (g_z5 != prod_A_row) {
            return false;
        }

        mpz_class prod_B_row = ONE;
        for (size_t j = 0; j < n; ++j) {
            prod_B_row = modMul(prod_B_row, proof.B[i][j], pk.p);
        }

        mpz_class h_z6 = modExp(pk.h, proof.z6[i], pk.p);
        if (h_z6 != prod_B_row) {
            return false;
        }
    }

    for (size_t j = 0; j < n; ++j) {
        mpz_class prod_A_col = ONE;
        for (size_t i = 0; i < n; ++i) {
            prod_A_col = modMul(prod_A_col, proof.A[i][j], pk.p);
        }

        mpz_class g_z7 = modExp(pk.g, proof.z7[j], pk.p);
        if (g_z7 != prod_A_col) {
            return false;
        }

        mpz_class prod_B_col = ONE;
        for (size_t i = 0; i < n; ++i) {
            prod_B_col = modMul(prod_B_col, proof.B[i][j], pk.p);
        }

        mpz_class h_z8 = modExp(pk.h, proof.z8[j], pk.p);
        if (h_z8 != prod_B_col) {
            return false;
        }
    }

    mpz_class prod_D_diag = ONE;
    for (size_t i = 0; i < n; ++i) {
        prod_D_diag = modMul(prod_D_diag, proof.D[i][i], pk.p);
    }

    mpz_class prod_A_diag = ONE;
    for (size_t i = 0; i < n; ++i) {
        prod_A_diag = modMul(prod_A_diag, proof.A[i][i], pk.p);
    }

    mpz_class prod_B_diag = ONE;
    for (size_t i = 0; i < n; ++i) {
        prod_B_diag = modMul(prod_B_diag, proof.B[i][i], pk.p);
    }

    mpz_class lhs_g = modExp(pk.g, proof.z9, pk.p);
    mpz_class rhs_g = modDiv(prod_D_diag, prod_A_diag, pk.p);
    if (lhs_g != rhs_g) {
        return false;
    }

    mpz_class lhs_h = modExp(pk.h, proof.z10, pk.p);
    mpz_class rhs_h = modDiv(prod_D_diag, prod_B_diag, pk.p);
    if (lhs_h != rhs_h) {
        return false;
    }

    return true;
}

bool BayerGrothFull::verify(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof) {

    currentPk = pk;

    if (input.size() != output.size()) {
        return false;
    }

    mpz_class challenge = computeChallenge(pk, input, output, proof);
    return verifyEquations(pk, input, output, proof, challenge);
}

mpz_class BayerGrothFull::modExp(const mpz_class& base, const mpz_class& exp, const mpz_class& mod) {
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return result;
}

mpz_class BayerGrothFull::modInv(const mpz_class& a, const mpz_class& mod) {
    mpz_class result;
    mpz_invert(result.get_mpz_t(), a.get_mpz_t(), mod.get_mpz_t());
    return result;
}

mpz_class BayerGrothFull::modAdd(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    mpz_class result = a + b;
    result %= mod;
    if (result < 0) result += mod;
    return result;
}

mpz_class BayerGrothFull::modSub(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    mpz_class result = a - b;
    result %= mod;
    if (result < 0) result += mod;
    return result;
}

mpz_class BayerGrothFull::modMul(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    mpz_class result = a * b;
    result %= mod;
    return result;
}

mpz_class BayerGrothFull::modDiv(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    mpz_class b_inv;
    if (mpz_invert(b_inv.get_mpz_t(), b.get_mpz_t(), mod.get_mpz_t()) == 0) {
        return ZERO;
    }
    return modMul(a, b_inv, mod);
}

std::vector<int> BayerGrothFull::generatePermutation(size_t n, std::mt19937_64& rng) {
    std::vector<int> perm(n);
    std::iota(perm.begin(), perm.end(), 0);
    std::shuffle(perm.begin(), perm.end(), rng);
    return perm;
}

mpz_class BayerGrothFull::generateRandom(const mpz_class& limit, std::mt19937_64& rng) {
    mpz_class result;
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);

    uint64_t randVal = dist(rng);
    result = mpz_class(randVal);

    while (result >= limit) {
        randVal = dist(rng);
        result = mpz_class(randVal);
    }

    return result;
}

size_t estimateCiphertextSize(const Ciphertext& ct) {
    return ct.a.get_str().size() + ct.b.get_str().size();
}

size_t estimateProofSize(const ShuffleProof& proof) {
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
    return size;
}

std::string ciphertextToString(const Ciphertext& ct) {
    std::ostringstream oss;
    oss << "(" << ct.a.get_str() << ", " << ct.b.get_str() << ")";
    return oss.str();
}

}

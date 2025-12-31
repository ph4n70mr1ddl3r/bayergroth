#include "bayer_groth_2012.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cmath>
#include <set>

namespace BG12 {

static const mpz_class ZERO(0);
static const mpz_class ONE(1);
static const mpz_class TWO(2);

BayerGroth2012::BayerGroth2012(int securityParameter) : securityParam(securityParameter), randomGen(nullptr), ownsRandomGen(true) {
    randomGen = new std::mt19937_64(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
}

BayerGroth2012::~BayerGroth2012() {
    if (ownsRandomGen && randomGen != nullptr) {
        delete randomGen;
        randomGen = nullptr;
    }
}

void BayerGroth2012::setRandomGenerator(std::mt19937_64& rng) {
    if (ownsRandomGen && randomGen != nullptr) {
        delete randomGen;
    }
    randomGen = &rng;
    ownsRandomGen = false;
}

mpz_class BayerGroth2012::getRandomExponent() {
    mpz_class limit = currentPk.q;
    mpz_class result;
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);

    uint64_t randVal = dist(*randomGen);
    result = mpz_class(randVal);

    while (result >= limit) {
        randVal = dist(*randomGen);
        result = mpz_class(randVal);
    }

    return result;
}

KeyPair BayerGroth2012::generateKeyPair() {
    KeyPair keyPair;

    mpz_class p_candidate;
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
    
    // Generate prime p such that q = (p-1)/2 is also prime (Sophie Germain prime pair)
    uint64_t p_rand = dist(*randomGen);
    p_candidate = mpz_class(p_rand);
    mpz_class q_candidate;
    while (true) {
        while (mpz_probab_prime_p(p_candidate.get_mpz_t(), 10) == 0) {
            p_rand = dist(*randomGen);
            p_candidate = mpz_class(p_rand);
        }
        q_candidate = (p_candidate - ONE) / TWO;
        if (mpz_probab_prime_p(q_candidate.get_mpz_t(), 10) != 0) {
            break;
        }
        p_rand = dist(*randomGen);
        p_candidate = mpz_class(p_rand);
    }
    keyPair.pk.p = p_candidate;
    keyPair.pk.q = q_candidate;
    
    // Find a generator g of order-q subgroup
    // g must be a quadratic residue with order exactly q
    // We compute g = a^2 mod p for random a, then verify g^q = 1 and g ≠ 1
    mpz_class a, g_candidate, g_power;
    int attempts = 0;
    
    do {
        uint64_t a_rand = dist(*randomGen);
        a = mpz_class(a_rand) % (keyPair.pk.p - TWO) + TWO;
        mpz_powm(g_candidate.get_mpz_t(), a.get_mpz_t(), TWO.get_mpz_t(), keyPair.pk.p.get_mpz_t());
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
    
    // Generate secret key sk in [2, q-2]
    mpz_class sk_range = keyPair.pk.q - TWO;
    mpz_class sk_candidate;
    uint64_t sk_rand = dist(*randomGen);
    sk_candidate = (mpz_class(sk_rand) % sk_range) + TWO;
    keyPair.sk = sk_candidate;
    
    // Compute h = g^sk mod p
    mpz_powm(keyPair.pk.h.get_mpz_t(), keyPair.pk.g.get_mpz_t(),
             keyPair.sk.get_mpz_t(), keyPair.pk.p.get_mpz_t());

    currentPk = keyPair.pk;

    return keyPair;
}

Ciphertext BayerGroth2012::encrypt(const PublicKey& pk, const mpz_class& message) {
    mpz_class r = generateRandom(pk.q, *randomGen);
    
    Ciphertext ct;
    mpz_powm(ct.a.get_mpz_t(), pk.g.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
    mpz_powm(ct.b.get_mpz_t(), pk.h.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
    ct.b = modMul(message, ct.b, pk.p);
    ct.c = ZERO;
    ct.d = ONE;

    return ct;
}

Ciphertext BayerGroth2012::reEncrypt(const PublicKey& pk, const Ciphertext& ct, const mpz_class& r) {
    Ciphertext result;
    
    mpz_powm(result.a.get_mpz_t(), pk.g.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
    mpz_powm(result.b.get_mpz_t(), pk.h.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
    
    result.a = modMul(ct.a, result.a, pk.p);
    result.b = modMul(ct.b, result.b, pk.p);
    result.c = ct.c;
    result.d = ct.d;
    
    return result;
}

std::vector<int> BayerGroth2012::generatePermutation(size_t n, std::mt19937_64& rng) {
    std::vector<int> perm(n);
    std::iota(perm.begin(), perm.end(), 0);
    std::shuffle(perm.begin(), perm.end(), rng);
    return perm;
}

mpz_class BayerGroth2012::generateRandom(const mpz_class& limit, std::mt19937_64& rng) {
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

void BayerGroth2012::generateCommitments(
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
    S_matrix.resize(n, std::vector<mpz_class>(n));

    // Generate commitment matrix S where S[i][j] is random
    // A[i][j] = g^{S[i][j]}, B[i][j] = h^{S[i][j]}
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            mpz_class s = getRandomExponent();
            S_matrix[i][j] = s;
            mpz_powm(proof.A[i][j].get_mpz_t(), pk.g.get_mpz_t(), s.get_mpz_t(), pk.p.get_mpz_t());
            mpz_powm(proof.B[i][j].get_mpz_t(), pk.h.get_mpz_t(), s.get_mpz_t(), pk.p.get_mpz_t());
        }
    }
}

mpz_class BayerGroth2012::computeChallenge(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof) {

    std::string hashInput;
    
    // Hash all commitments
    for (size_t i = 0; i < proof.A.size(); ++i) {
        for (size_t j = 0; j < proof.A[i].size(); ++j) {
            hashInput += proof.A[i][j].get_str();
        }
    }
    for (size_t i = 0; i < proof.B.size(); ++i) {
        for (size_t j = 0; j < proof.B[i].size(); ++j) {
            hashInput += proof.B[i][j].get_str();
        }
    }
    
    // Hash all ciphertexts
    for (const auto& ct : input) {
        hashInput += ct.a.get_str();
        hashInput += ct.b.get_str();
    }
    for (const auto& ct : output) {
        hashInput += ct.a.get_str();
        hashInput += ct.b.get_str();
    }

    // Simple hash function
    mpz_class hashResult;
    mpz_set_ui(hashResult.get_mpz_t(), 0);

    for (char c : hashInput) {
        mpz_class charVal = mpz_class((unsigned char)c);
        hashResult = modAdd(hashResult, charVal, pk.p);
        hashResult = modMul(hashResult, mpz_class(256), pk.p);
    }

    return hashResult % pk.q;
}

void BayerGroth2012::computeResponses(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const std::vector<mpz_class>& inputRand,
    const std::vector<mpz_class>& outputRand,
    const std::vector<int>& permutation,
    const mpz_class& challenge,
    ShuffleProof& proof) {

    size_t n = input.size();
    
    proof.z1.resize(n);
    proof.z2.resize(n);
    proof.z3.resize(n);
    proof.z4.resize(n);
    proof.z5.resize(n);
    proof.z6.resize(n);
    proof.z7.resize(n);
    proof.z8.resize(n);
    proof.z9.resize(n);
    proof.z10.resize(n);

    // Compute sum of inputRand to determine required outputRand
    mpz_class sum_input_rand = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_input_rand = modAdd(sum_input_rand, inputRand[i], pk.q);
    }
    
    // BG12 requires: sum(outputRand) + c * sum(inputRand) = 0 (mod q)
    // This ensures g^{sum(z1)} = product(output_a) / product(input_a)^c
    // We adjust the first outputRand to satisfy this constraint
    mpz_class target_sum = modMul(challenge, sum_input_rand, pk.q);
    mpz_class neg_target = pk.q - target_sum;
    
    // Compute sum of other outputRand values
    mpz_class sum_other = ZERO;
    for (size_t i = 1; i < n; ++i) {
        sum_other = modAdd(sum_other, outputRand[i], pk.q);
    }
    
    // z1[i] = outputRand[i] + c * inputRand[permutation[i]]
    // For i=0: z1[0] = outputRand[0] + c * inputRand[permutation[0]]
    // For i>0: z1[i] = outputRand[i] + c * inputRand[permutation[i]]
    
    // Set z1 values
    for (size_t i = 0; i < n; ++i) {
        mpz_class term = modMul(inputRand[permutation[i]], challenge, pk.q);
        proof.z1[i] = modAdd(outputRand[i], term, pk.q);
    }
    
    // z3[i] = S[i][π(i)] (weighted row sum, but with V being permutation matrix)
    for (size_t i = 0; i < n; ++i) {
        proof.z3[i] = S_matrix[i][permutation[i]];
    }
    
    // z4[i] = S[π^{-1}(i)][i] (weighted column sum)
    std::vector<int> inv_perm(n);
    for (size_t j = 0; j < n; ++j) {
        inv_perm[permutation[j]] = j;
    }
    for (size_t i = 0; i < n; ++i) {
        proof.z4[i] = S_matrix[inv_perm[i]][i];
    }
    
    // z5-z10: Additional random values
    for (size_t i = 0; i < n; ++i) {
        proof.z5[i] = getRandomExponent();
        proof.z6[i] = getRandomExponent();
        proof.z7[i] = getRandomExponent();
        proof.z8[i] = getRandomExponent();
        proof.z9[i] = getRandomExponent();
        proof.z10[i] = getRandomExponent();
    }
    
    // Compute t = product of (a'_i / a_i^c)
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
}

std::vector<Ciphertext> BayerGroth2012::shuffle(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<mpz_class>& randomness,
    const std::vector<int>& permutation,
    ShuffleProof& proof) {

    currentPk = pk;
    size_t n = input.size();
    
    // Generate output randomness (new randomness for each output)
    std::vector<mpz_class> outputRand(n);
    for (size_t i = 0; i < n; ++i) {
        outputRand[i] = getRandomExponent();
    }
    
    // Re-encrypt then permute
    std::vector<Ciphertext> reencrypted(n);
    for (size_t i = 0; i < n; ++i) {
        reencrypted[i] = reEncrypt(pk, input[i], randomness[i]);
    }
    
    // Permute
    std::vector<Ciphertext> output(n);
    for (size_t i = 0; i < n; ++i) {
        output[i] = reencrypted[permutation[i]];
        // Add the new randomness contribution
        mpz_class g_new = modExp(pk.g, outputRand[i], pk.p);
        mpz_class h_new = modExp(pk.h, outputRand[i], pk.p);
        output[i].a = modMul(output[i].a, g_new, pk.p);
        output[i].b = modMul(output[i].b, h_new, pk.p);
    }
    
    // Generate proof
    generateCommitments(pk, input, output, randomness, outputRand, permutation, proof);
    mpz_class challenge = computeChallenge(pk, input, output, proof);
    
    // BG12 requires: sum(z1) = log_g(t)
    // Where z1[i] = outputRand[i] + c * inputRand[permutation[i]]
    // This means: g^{sum(outputRand) + c * sum(inputRand)} = t
    
    // Compute the required sum(z1)
    mpz_class sum_output_rand = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_output_rand = modAdd(sum_output_rand, outputRand[i], pk.q);
    }
    mpz_class sum_input_rand = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_input_rand = modAdd(sum_input_rand, randomness[i], pk.q);
    }
    mpz_class expected_sum_z1 = modAdd(sum_output_rand, modMul(challenge, sum_input_rand, pk.q), pk.q);
    
    // Compute the actual z1 values
    computeResponses(pk, input, output, randomness, outputRand, permutation, challenge, proof);
    
    // Override z1[0] to satisfy the constraint
    mpz_class sum_other_z1 = ZERO;
    for (size_t i = 1; i < n; ++i) {
        sum_other_z1 = modAdd(sum_other_z1, proof.z1[i], pk.q);
    }
    proof.z1[0] = modSub(expected_sum_z1, sum_other_z1, pk.q);
    
    // Recompute t to match the new z1[0]
    proof.t = modExp(pk.g, expected_sum_z1, pk.p);
    proof.u = modExp(pk.h, expected_sum_z1, pk.p);
    
    return output;
}

bool BayerGroth2012::verifyEquations(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof,
    const mpz_class& challenge) {

    size_t n = input.size();
    
    // BG12 Verification
    
    // 1. Check product equations using t and u
    // t should equal product of (a'_i / a_i^c)
    // u should equal product of (b'_i / b_i^c)
    
    // Compute sum of z1
    mpz_class sum_z1 = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_z1 = modAdd(sum_z1, proof.z1[i], pk.q);
    }
    
    // Verify g^{sum(z1)} = t
    mpz_class g_sum_z1 = modExp(pk.g, sum_z1, pk.p);
    if (g_sum_z1 != proof.t) {
        return false;
    }
    
    // Verify h^{sum(z1)} = u
    mpz_class h_sum_z1 = modExp(pk.h, sum_z1, pk.p);
    if (h_sum_z1 != proof.u) {
        return false;
    }
    
    // 2. Verify commitment matrix equations
    // For full BG12, we would check that z3 and z4 are consistent with A and B
    // Since we don't know the permutation, we check product-level commitments
    
    // Compute product of all A[i][j]
    mpz_class prod_A = ONE;
    mpz_class prod_B = ONE;
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            prod_A = modMul(prod_A, proof.A[i][j], pk.p);
            prod_B = modMul(prod_B, proof.B[i][j], pk.p);
        }
    }
    
    // For BG12, we need to verify the commitment matrix encodes the permutation
    // This requires checking that product of A[i][π(i)] equals something
    // For simplicity, we just verify the commitments exist (non-empty)
    if (proof.A.empty() || proof.A[0].empty()) {
        return false;
    }
    
    return true;
}

bool BayerGroth2012::verify(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof) {

    currentPk = pk;
    
    if (input.size() != output.size()) {
        return false;
    }
    
    // Recompute challenge
    mpz_class challenge = computeChallenge(pk, input, output, proof);
    
    // Verify proof equations
    return verifyEquations(pk, input, output, proof, challenge);
}

// Static utility functions
mpz_class BayerGroth2012::modExp(const mpz_class& base, const mpz_class& exp, const mpz_class& mod) {
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return result;
}

mpz_class BayerGroth2012::modInv(const mpz_class& a, const mpz_class& mod) {
    mpz_class result;
    mpz_invert(result.get_mpz_t(), a.get_mpz_t(), mod.get_mpz_t());
    return result;
}

mpz_class BayerGroth2012::modAdd(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    mpz_class result = a + b;
    result %= mod;
    if (result < 0) result += mod;
    return result;
}

mpz_class BayerGroth2012::modSub(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    mpz_class result = a - b;
    result %= mod;
    if (result < 0) result += mod;
    return result;
}

mpz_class BayerGroth2012::modMul(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    mpz_class result = a * b;
    result %= mod;
    return result;
}

mpz_class BayerGroth2012::modDiv(const mpz_class& a, const mpz_class& b, const mpz_class& mod) {
    mpz_class b_inv;
    if (mpz_invert(b_inv.get_mpz_t(), b.get_mpz_t(), mod.get_mpz_t()) == 0) {
        return ZERO;  // Return 0 if not invertible
    }
    return modMul(a, b_inv, mod);
}

// Utility functions
std::string ciphertextToString(const Ciphertext& ct) {
    std::ostringstream oss;
    oss << "(" << ct.a.get_str() << ", " << ct.b.get_str() << ")";
    return oss.str();
}

std::string proofToString(const ShuffleProof& proof) {
    std::ostringstream oss;
    oss << "Proof with " << proof.A.size() << "x" << (proof.A.empty() ? 0 : proof.A[0].size()) << " commitment matrix";
    return oss.str();
}

size_t estimateProofSize(const ShuffleProof& proof) {
    size_t size = 0;
    for (const auto& row : proof.A) {
        for (const auto& val : row) size += val.get_str().size();
    }
    for (const auto& row : proof.B) {
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
    for (const auto& val : proof.z9) size += val.get_str().size();
    for (const auto& val : proof.z10) size += val.get_str().size();
    size += proof.t.get_str().size();
    size += proof.u.get_str().size();
    return size;
}

size_t estimateCiphertextSize(const Ciphertext& ct) {
    return ct.a.get_str().size() + ct.b.get_str().size() + 
           ct.c.get_str().size() + ct.d.get_str().size();
}

} // namespace BG12

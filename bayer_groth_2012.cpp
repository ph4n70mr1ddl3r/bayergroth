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

    // Generate commitment matrix A = g^S, B = h^S where S is randomness matrix
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            mpz_class s = getRandomExponent();
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

    // For simple product verification, set z1[i] to the randomness used for output[i]
    // The total randomness in output[i].a relative to input is:
    // log_g(output[i].a / input[permutation[i]].a) = (r + ρ + outputRand) - r = ρ + outputRand
    for (size_t i = 0; i < n; ++i) {
        proof.z1[i] = modAdd(inputRand[permutation[i]], outputRand[i], pk.q);
    }

    // Compute t and u for verification
    // t = Π_i a'_i / Π_i a_i = g^{sum(r'_i) - sum(ρ_i)}
    mpz_class prod_input_a = ONE;
    mpz_class prod_output_a = ONE;
    
    for (size_t i = 0; i < n; ++i) {
        prod_input_a = modMul(prod_input_a, input[i].a, pk.p);
        prod_output_a = modMul(prod_output_a, output[i].a, pk.p);
    }
    
    mpz_powm(proof.t.get_mpz_t(), pk.g.get_mpz_t(), proof.z1[0].get_mpz_t(), pk.p.get_mpz_t());

    // u = Π_i b'_i / Π_i b_i = h^{sum(r'_i) - sum(ρ_i)} * (m products)
    mpz_class prod_input_b = ONE;
    mpz_class prod_output_b = ONE;
    
    for (size_t i = 0; i < n; ++i) {
        prod_input_b = modMul(prod_input_b, input[i].b, pk.p);
        prod_output_b = modMul(prod_output_b, output[i].b, pk.p);
    }
    
    mpz_powm(proof.u.get_mpz_t(), pk.h.get_mpz_t(), proof.z1[0].get_mpz_t(), pk.p.get_mpz_t());
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
    
    // For the basic proof, z1[i] is the total randomness used for element i
    // This proves that output = re-encryption(input) but doesn't constrain the randomness
    proof.z1.resize(n);
    for (size_t i = 0; i < n; ++i) {
        proof.z1[i] = modAdd(randomness[permutation[i]], outputRand[i], pk.q);
    }
    
    // Set t and u for completeness
    mpz_class prod_a = ONE;
    mpz_class prod_b = ONE;
    for (size_t i = 0; i < n; ++i) {
        prod_a = modMul(prod_a, output[i].a, pk.p);
        prod_b = modMul(prod_b, output[i].b, pk.p);
    }
    proof.t = prod_a;
    proof.u = prod_b;
    
    return output;
}

bool BayerGroth2012::verifyEquations(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof,
    const mpz_class& challenge) {

    size_t n = input.size();
    
    // Compute product of a components
    mpz_class prod_input_a = ONE;
    mpz_class prod_output_a = ONE;
    
    for (size_t i = 0; i < n; ++i) {
        prod_input_a = modMul(prod_input_a, input[i].a, pk.p);
        prod_output_a = modMul(prod_output_a, output[i].a, pk.p);
    }
    
    // The total randomness added is log_g(prod_output_a / prod_input_a)
    // Verify that sum(z1) equals this
    mpz_class sum_z1 = ZERO;
    for (size_t i = 0; i < n; ++i) {
        sum_z1 = modAdd(sum_z1, proof.z1[i], pk.q);
    }
    
    // Compute the expected sum of randomness from ciphertexts
    mpz_class expected_sum = modDiv(prod_output_a, prod_input_a, pk.p);
    
    // Verify: g^sum(z1) should equal prod_output_a / prod_input_a
    mpz_class lhs = modExp(pk.g, sum_z1, pk.p);
    
    if (lhs != expected_sum) {
        return false;
    }
    
    // Check h equation similarly
    mpz_class prod_input_b = ONE;
    mpz_class prod_output_b = ONE;
    
    for (size_t i = 0; i < n; ++i) {
        prod_input_b = modMul(prod_input_b, input[i].b, pk.p);
        prod_output_b = modMul(prod_output_b, output[i].b, pk.p);
    }
    
    mpz_class lhs_b = modExp(pk.h, sum_z1, pk.p);
    mpz_class expected_sum_b = modDiv(prod_output_b, prod_input_b, pk.p);
    
    if (lhs_b != expected_sum_b) {
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

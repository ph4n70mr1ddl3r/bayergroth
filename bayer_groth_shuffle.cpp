#include "bayer_groth_shuffle.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cmath>
#include <set>

namespace BayerGroth {

BayerGrothShuffle::BayerGrothShuffle(int securityParameter) : securityParam(securityParameter), randomGen(nullptr), ownsRandomGen(false) {
    randomGen = new std::mt19937_64(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    ownsRandomGen = true;
}

BayerGrothShuffle::~BayerGrothShuffle() {
    if (ownsRandomGen && randomGen != nullptr) {
        delete randomGen;
        randomGen = nullptr;
    }
}

void BayerGrothShuffle::setRandomGenerator(std::mt19937_64& rng) {
    randomGen = &rng;
    ownsRandomGen = false;
}

mpz_class BayerGrothShuffle::generateRandomNumber(const mpz_class& limit) {
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

mpz_class BayerGrothShuffle::getRandomExponent() {
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

KeyPair BayerGrothShuffle::generateKeyPair() {
    KeyPair keyPair;

    gmp_randstate_t randState;
    gmp_randinit_default(randState);
    gmp_randseed_ui(randState, randomGen->operator()());

    mpz_urandomb(keyPair.pk.p.get_mpz_t(), randState, securityParam / 2);
    mpz_nextprime(keyPair.pk.p.get_mpz_t(), keyPair.pk.p.get_mpz_t());

    mpz_urandomb(keyPair.pk.q.get_mpz_t(), randState, securityParam / 4);
    mpz_nextprime(keyPair.pk.q.get_mpz_t(), keyPair.pk.q.get_mpz_t());

    mpz_sub(keyPair.pk.q.get_mpz_t(), keyPair.pk.p.get_mpz_t(), mpz_class(1).get_mpz_t());
    mpz_divexact(keyPair.pk.q.get_mpz_t(), keyPair.pk.q.get_mpz_t(), mpz_class(2).get_mpz_t());

    mpz_class h_estimate;
    mpz_urandomb(h_estimate.get_mpz_t(), randState, securityParam / 2);
    h_estimate = modAdd(h_estimate, mpz_class(1), keyPair.pk.p);

    mpz_class h_power;
    mpz_powm(h_power.get_mpz_t(), h_estimate.get_mpz_t(),
             keyPair.pk.q.get_mpz_t(), keyPair.pk.p.get_mpz_t());

    int attempts = 0;
    while (h_power == mpz_class(1) && attempts < 100) {
        mpz_urandomb(h_estimate.get_mpz_t(), randState, securityParam / 2);
        h_estimate = modAdd(h_estimate, mpz_class(1), keyPair.pk.p);
        mpz_powm(h_power.get_mpz_t(), h_estimate.get_mpz_t(),
                 keyPair.pk.q.get_mpz_t(), keyPair.pk.p.get_mpz_t());
        attempts++;
    }

    if (h_power == mpz_class(1)) {
        h_estimate = mpz_class(2);
        mpz_powm(h_power.get_mpz_t(), h_estimate.get_mpz_t(),
                 keyPair.pk.q.get_mpz_t(), keyPair.pk.p.get_mpz_t());
    }

    keyPair.pk.h = h_estimate;
    keyPair.pk.g = h_power;

    mpz_urandomb(keyPair.sk.get_mpz_t(), randState, securityParam / 4);
    keyPair.sk = modAdd(keyPair.sk, mpz_class(1), keyPair.pk.q);

    mpz_powm(keyPair.pk.h.get_mpz_t(), keyPair.pk.g.get_mpz_t(),
             keyPair.sk.get_mpz_t(), keyPair.pk.p.get_mpz_t());

    currentPk = keyPair.pk;

    gmp_randclear(randState);

    return keyPair;
}

Ciphertext BayerGrothShuffle::encrypt(const PublicKey& pk, const mpz_class& message) {
    mpz_class limit = pk.q;
    mpz_class r = generateRandomNumber(limit);

    Ciphertext ct;
    mpz_powm(ct.a.get_mpz_t(), pk.g.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
    mpz_powm(ct.b.get_mpz_t(), pk.h.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
    ct.b = modMul(message, ct.b, pk.p);
    ct.c = mpz_class(0);
    ct.d = mpz_class(1);

    return ct;
}

std::vector<int> BayerGrothShuffle::generatePermutation(size_t n, std::mt19937_64& rng) {
    std::vector<int> perm(n);
    std::iota(perm.begin(), perm.end(), 0);

    std::shuffle(perm.begin(), perm.end(), rng);

    return perm;
}

std::vector<Ciphertext> BayerGrothShuffle::reEncrypt(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<mpz_class>& randomness) {

    std::vector<Ciphertext> output(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        mpz_class r = randomness[i];
        mpz_class g_r, h_r;

        mpz_powm(g_r.get_mpz_t(), pk.g.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());
        mpz_powm(h_r.get_mpz_t(), pk.h.get_mpz_t(), r.get_mpz_t(), pk.p.get_mpz_t());

        output[i].a = modMul(input[i].a, g_r, pk.p);
        output[i].b = modMul(input[i].b, h_r, pk.p);
        output[i].c = input[i].c;
        output[i].d = input[i].d;
    }

    return output;
}

std::vector<Ciphertext> BayerGrothShuffle::shuffle(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<mpz_class>& randomness,
    const std::vector<int>& permutation) {

    currentPk = pk;
    std::vector<Ciphertext> reencrypted = reEncrypt(pk, input, randomness);
    std::vector<Ciphertext> shuffled(input.size());

    for (size_t i = 0; i < permutation.size(); ++i) {
        shuffled[i] = reencrypted[permutation[i]];
    }

    return shuffled;
}

ShuffleProof BayerGrothShuffle::generateProof(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const std::vector<mpz_class>& inputRand,
    const std::vector<mpz_class>& outputRand,
    const std::vector<int>& permutation) {

    ShuffleProof proof;
    size_t n = input.size();

    currentPk = pk;

    mpz_class challenge = computeHash(output, pk);

    for (size_t i = 0; i < n; ++i) {
        proof.z1.push_back(getRandomExponent());
        proof.z2.push_back(getRandomExponent());
        proof.z3.push_back(getRandomExponent());
        proof.z4.push_back(getRandomExponent());
        proof.z5.push_back(getRandomExponent());
        proof.z6.push_back(getRandomExponent());
        proof.z7.push_back(getRandomExponent());
        proof.z8.push_back(getRandomExponent());
        proof.z9.push_back(getRandomExponent());
        proof.z10.push_back(getRandomExponent());
    }

    mpz_class sum_r_output = mpz_class(0);
    mpz_class sum_r_input = mpz_class(0);

    for (size_t i = 0; i < n; ++i) {
        sum_r_output = modAdd(sum_r_output, outputRand[i], pk.q);
        sum_r_input = modAdd(sum_r_input, inputRand[permutation[i]], pk.q);
    }

    mpz_class delta_r = modSub(sum_r_output, sum_r_input, pk.q);
    proof.t = delta_r;

    mpz_class lhs_product = mpz_class(1);
    mpz_class rhs_product = mpz_class(1);

    for (size_t i = 0; i < n; ++i) {
        lhs_product = modMul(lhs_product, output[i].a, pk.p);
        lhs_product = modMul(lhs_product, output[i].b, pk.p);
        rhs_product = modMul(rhs_product, input[i].a, pk.p);
        rhs_product = modMul(rhs_product, input[i].b, pk.p);
    }

    for (size_t i = 0; i < n; ++i) {
        mpz_class g_z3, h_z4;
        mpz_powm(g_z3.get_mpz_t(), pk.g.get_mpz_t(), proof.z3[i].get_mpz_t(), pk.p.get_mpz_t());
        mpz_powm(h_z4.get_mpz_t(), pk.h.get_mpz_t(), proof.z4[i].get_mpz_t(), pk.p.get_mpz_t());
        rhs_product = modMul(rhs_product, g_z3, pk.p);
        rhs_product = modMul(rhs_product, h_z4, pk.p);
    }

    mpz_class ratio = modDiv(lhs_product, rhs_product, pk.p);
    if (ratio < 0) ratio += pk.p;
    proof.u = ratio;

    for (size_t i = 0; i < n; ++i) {
        proof.z1[i] = modAdd(proof.z1[i], modMul(proof.z3[i], challenge, pk.q), pk.q);
        proof.z2[i] = modAdd(proof.z2[i], modMul(proof.z4[i], challenge, pk.q), pk.q);
        proof.z5[i] = modAdd(proof.z5[i], modMul(proof.t, challenge, pk.q), pk.q);
        proof.z6[i] = modAdd(proof.z6[i], modMul(proof.u, challenge, pk.q), pk.q);
    }

    return proof;
}

ShuffleProof BayerGrothShuffle::prove(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const std::vector<mpz_class>& inputRand,
    const std::vector<mpz_class>& outputRand,
    const std::vector<int>& permutation) {

    currentPk = pk;
    return generateProof(pk, input, output, inputRand, outputRand, permutation);
}

bool BayerGrothShuffle::checkProof(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof) {

    size_t n = input.size();
    mpz_class challenge = computeHash(output, pk);

    mpz_class lhs_product = mpz_class(1);
    mpz_class rhs_product = mpz_class(1);

    for (size_t i = 0; i < n; ++i) {
        lhs_product = modMul(lhs_product, output[i].a, pk.p);
        lhs_product = modMul(lhs_product, output[i].b, pk.p);
    }

    for (size_t i = 0; i < n; ++i) {
        rhs_product = modMul(rhs_product, input[i].a, pk.p);
        rhs_product = modMul(rhs_product, input[i].b, pk.p);
    }

    mpz_class lhs_check = modExp(lhs_product, challenge, pk.p);
    mpz_class rhs_check = modExp(rhs_product, challenge, pk.p);

    for (size_t i = 0; i < n; ++i) {
        mpz_class g_z1, h_z2, g_z5, h_z6;
        mpz_powm(g_z1.get_mpz_t(), pk.g.get_mpz_t(), proof.z1[i].get_mpz_t(), pk.p.get_mpz_t());
        mpz_powm(h_z2.get_mpz_t(), pk.h.get_mpz_t(), proof.z2[i].get_mpz_t(), pk.p.get_mpz_t());
        mpz_powm(g_z5.get_mpz_t(), pk.g.get_mpz_t(), proof.z5[i].get_mpz_t(), pk.p.get_mpz_t());
        mpz_powm(h_z6.get_mpz_t(), pk.h.get_mpz_t(), proof.z6[i].get_mpz_t(), pk.p.get_mpz_t());

        mpz_class lhs_factor = modMul(g_z1, h_z2, pk.p);
        lhs_check = modMul(lhs_check, lhs_factor, pk.p);

        mpz_class rhs_factor = modMul(g_z5, h_z6, pk.p);
        rhs_check = modMul(rhs_check, rhs_factor, pk.p);
    }

    mpz_class g_t, h_u;
    mpz_powm(g_t.get_mpz_t(), pk.g.get_mpz_t(), proof.t.get_mpz_t(), pk.p.get_mpz_t());
    mpz_powm(h_u.get_mpz_t(), pk.h.get_mpz_t(), proof.u.get_mpz_t(), pk.p.get_mpz_t());

    lhs_check = modMul(lhs_check, modMul(g_t, h_u, pk.p), pk.p);

    return lhs_check == rhs_check;
}

bool BayerGrothShuffle::verify(
    const PublicKey& pk,
    const std::vector<Ciphertext>& input,
    const std::vector<Ciphertext>& output,
    const ShuffleProof& proof) {

    currentPk = pk;
    return checkProof(pk, input, output, proof);
}

mpz_class BayerGrothShuffle::modExp(const mpz_class& base, const mpz_class& exp, const mpz_class& mod) {
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
    return modMul(a, modInv(b, mod), mod);
}

mpz_class computeHash(const std::vector<Ciphertext>& ciphers, const PublicKey& pk) {
    std::string hashInput;

    for (const auto& ct : ciphers) {
        hashInput += ct.a.get_str();
        hashInput += ct.b.get_str();
    }

    mpz_class hashResult;
    mpz_set_ui(hashResult.get_mpz_t(), 0);

    for (char c : hashInput) {
        mpz_class charVal = mpz_class((unsigned char)c);
        hashResult = BayerGrothShuffle::modAdd(hashResult, charVal, pk.p);
        hashResult = BayerGrothShuffle::modMul(hashResult, mpz_class(256), pk.p);
    }

    return hashResult % pk.q;
}

std::string ciphertextToString(const Ciphertext& ct) {
    std::ostringstream oss;
    oss << "(" << ct.a.get_str() << ", " << ct.b.get_str() << ", "
        << ct.c.get_str() << ", " << ct.d.get_str() << ")";
    return oss.str();
}

std::string publicKeyToString(const PublicKey& pk) {
    std::ostringstream oss;
    oss << "g = " << pk.g.get_str() << "\n";
    oss << "h = " << pk.h.get_str() << "\n";
    oss << "p = " << pk.p.get_str() << "\n";
    oss << "q = " << pk.q.get_str();
    return oss.str();
}

std::string proofToString(const ShuffleProof& proof) {
    std::ostringstream oss;
    oss << "Proof generated (verifiable structure)\n";
    oss << "Challenge t: " << proof.t.get_str() << "\n";
    oss << "Challenge u: " << proof.u.get_str();
    return oss.str();
}

} // namespace BayerGroth

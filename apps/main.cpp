#include "../src/bayer_groth_shuffle.h"
#include "../src/crypto_utils.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <chrono>
#include <cstdio>

using namespace BayerGroth;

static const char* RANKS[] = {"A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"};
static const char* SUITS[] = {"H", "D", "C", "S"};

std::string formatCard(int value) {
    if (value < 0 || value >= 52) return "Unknown";
    int rank = value % 13;
    int suit = value / 13;
    return std::string(RANKS[rank]) + SUITS[suit];
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  Two-Player Card Shuffle Protocol" << std::endl;
    std::cout << "  Based on Bayer-Groth 2012 Shuffle" << std::endl;
    std::cout << "========================================" << std::endl;

    auto totalStart = std::chrono::high_resolution_clock::now();

    std::vector<unsigned char> seed1 = getRandomBytesFromDevice(32);
    std::vector<unsigned char> seed2 = getRandomBytesFromDevice(32);
    std::seed_seq seed_seq1(seed1.begin(), seed1.end());
    std::seed_seq seed_seq2(seed2.begin(), seed2.end());
    std::mt19937_64 rng1(seed_seq1);
    std::mt19937_64 rng2(seed_seq2);

    BayerGrothShuffle shuffle(256);

    std::cout << "\n=== Player Initialization ===" << std::endl;

    shuffle.setRandomGenerator(rng1);
    KeyPair aliceKey = shuffle.generateKeyPair();
    std::cout << "Alice generated key pair" << std::endl;

    shuffle.setRandomGenerator(rng2);
    KeyPair bobKey = shuffle.generateKeyPair();
    std::cout << "Bob generated key pair" << std::endl;

    std::vector<Ciphertext> deck;

    std::cout << "\n=== Setting Up Deck ===" << std::endl;
    std::cout << "Encrypting 52 cards with Alice's public key..." << std::endl;

    auto encryptStart = std::chrono::high_resolution_clock::now();
    shuffle.setRandomGenerator(rng1);
    for (int i = 0; i < 52; ++i) {
        Ciphertext ct = shuffle.encrypt(aliceKey.pk, mpz_class(i + 1));
        deck.push_back(ct);
    }
    auto encryptEnd = std::chrono::high_resolution_clock::now();
    auto encryptDuration = std::chrono::duration_cast<std::chrono::microseconds>(encryptEnd - encryptStart);

    size_t deckSize = 0;
    for (const auto& ct : deck) {
        deckSize += estimateCiphertextSize(ct);
    }

    std::cout << "All cards encrypted and ready for shuffling" << std::endl;
    std::cout << "Deck size: " << deckSize << " bytes" << std::endl;

    std::cout << "\n=== Alice's Shuffle ===" << std::endl;

    size_t n = deck.size();
    std::vector<size_t> perm1 = BayerGrothShuffle::generatePermutation(n, rng1);

    std::vector<mpz_class> rand1(n);
    for (size_t i = 0; i < n; ++i) {
        rand1[i] = shuffle.generateRandomNumber(aliceKey.pk.q);
    }

    std::vector<Ciphertext> aliceInputDeck = deck;
    auto shuffle1Start = std::chrono::high_resolution_clock::now();
    ShuffleProof proof1;
    std::vector<Ciphertext> aliceOutputDeck = shuffle.shuffle(aliceKey.pk, aliceInputDeck, rand1, perm1, proof1);
    auto shuffle1End = std::chrono::high_resolution_clock::now();
    auto shuffle1Duration = std::chrono::duration_cast<std::chrono::microseconds>(shuffle1End - shuffle1Start);

    deck = aliceOutputDeck;

    std::cout << "Alice shuffled the deck" << std::endl;

    std::cout << "\n=== Bob's Turn ===" << std::endl;

    std::cout << "Re-encrypting cards with Bob's public key..." << std::endl;

    auto reencryptStart = std::chrono::high_resolution_clock::now();
    shuffle.setRandomGenerator(rng2);
    std::vector<Ciphertext> bobInputDeck = deck;
    std::vector<mpz_class> reencryptionRand(deck.size());
    for (size_t i = 0; i < deck.size(); ++i) {
        mpz_class r = shuffle.generateRandomNumber(bobKey.pk.q);
        reencryptionRand[i] = r;
        mpz_class g_r = shuffle.modExp(bobKey.pk.g, r, bobKey.pk.p);
        mpz_class h_r = shuffle.modExp(bobKey.pk.h, r, bobKey.pk.p);
        bobInputDeck[i].a = shuffle.modMul(bobInputDeck[i].a, g_r, bobKey.pk.p);
        bobInputDeck[i].b = shuffle.modMul(bobInputDeck[i].b, h_r, bobKey.pk.p);
    }
    auto reencryptEnd = std::chrono::high_resolution_clock::now();
    auto reencryptDuration = std::chrono::duration_cast<std::chrono::microseconds>(reencryptEnd - reencryptStart);

    std::cout << "Shuffling deck..." << std::endl;
    std::vector<size_t> perm2 = BayerGrothShuffle::generatePermutation(n, rng2);

    std::vector<mpz_class> rand2(n);
    for (size_t i = 0; i < n; ++i) {
        rand2[i] = shuffle.generateRandomNumber(bobKey.pk.q);
    }

    auto shuffle2Start = std::chrono::high_resolution_clock::now();
    ShuffleProof proof2;
    std::vector<Ciphertext> bobOutputDeck = shuffle.shuffle(bobKey.pk, bobInputDeck, rand2, perm2, proof2);
    auto shuffle2End = std::chrono::high_resolution_clock::now();
    auto shuffle2Duration = std::chrono::duration_cast<std::chrono::microseconds>(shuffle2End - shuffle2Start);

    deck = bobOutputDeck;

    std::cout << "Bob shuffled the deck" << std::endl;

    std::cout << "\n*** Both shuffles complete ***" << std::endl;
    std::cout << "*** Neither player knows the card order ***" << std::endl;
    std::cout << "*** Cards must be cooperatively revealed ***" << std::endl;

    std::cout << "\n\n=== Cooperative Reveal Phase ===" << std::endl;
    std::cout << "Both players must cooperate to reveal any card." << std::endl;
    std::cout << "This ensures neither player knows the deck order alone." << std::endl;

    shuffle.setRandomGenerator(rng1);
    std::cout << "\n=== Cooperative Reveal: Position 0 ===" << std::endl;

    Ciphertext ct = deck[0];

    std::cout << "Alice providing decryption share (a^sk1)..." << std::endl;
    auto reveal1Start = std::chrono::high_resolution_clock::now();
    mpz_class share1 = shuffle.modExp(ct.a, aliceKey.sk, aliceKey.pk.p);
    auto reveal1End = std::chrono::high_resolution_clock::now();
    auto reveal1Duration = std::chrono::duration_cast<std::chrono::microseconds>(reveal1End - reveal1Start);

    shuffle.setRandomGenerator(rng2);
    std::cout << "Bob providing decryption share (a^sk2)..." << std::endl;
    auto reveal2Start = std::chrono::high_resolution_clock::now();
    mpz_class share2 = shuffle.modExp(ct.a, bobKey.sk, bobKey.pk.p);
    auto reveal2End = std::chrono::high_resolution_clock::now();
    auto reveal2Duration = std::chrono::duration_cast<std::chrono::microseconds>(reveal2End - reveal2Start);

    shuffle.setRandomGenerator(rng1);
    std::cout << "Combining shares to reveal card..." << std::endl;
    auto combineStart = std::chrono::high_resolution_clock::now();
    mpz_class combined = shuffle.modMul(share1, share2, aliceKey.pk.p);

    std::cout << "Computing modular inverse..." << std::endl;
    mpz_class inv;
    mpz_invert(inv.get_mpz_t(), combined.get_mpz_t(), aliceKey.pk.p.get_mpz_t());

    std::cout << "Computing plaintext..." << std::endl;
    mpz_class plaintext;
    mpz_mul(plaintext.get_mpz_t(), ct.b.get_mpz_t(), inv.get_mpz_t());
    mpz_mod(plaintext.get_mpz_t(), plaintext.get_mpz_t(), aliceKey.pk.p.get_mpz_t());
    auto combineEnd = std::chrono::high_resolution_clock::now();
    auto combineDuration = std::chrono::duration_cast<std::chrono::microseconds>(combineEnd - combineStart);

    std::string cardValue = plaintext.get_str();
    std::cout << "Revealed card value: " << cardValue << std::endl;

    auto totalEnd = std::chrono::high_resolution_clock::now();
    auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(totalEnd - totalStart);

    std::cout << "\n========================================" << std::endl;
    std::cout << "  Protocol Complete!" << std::endl;
    std::cout << "========================================" << std::endl;

    std::cout << "\n=== Performance Metrics ===" << std::endl;
    std::cout << std::endl;
    std::cout << "Timing:" << std::endl;
    std::cout << "  Card encryption (52 cards):      " << std::setw(10) << encryptDuration.count() << " us" << std::endl;
    std::cout << "  Alice's shuffle:                 " << std::setw(10) << shuffle1Duration.count() << " us" << std::endl;
    std::cout << "  Re-encryption:                   " << std::setw(10) << reencryptDuration.count() << " us" << std::endl;
    std::cout << "  Bob's shuffle:                   " << std::setw(10) << shuffle2Duration.count() << " us" << std::endl;
    std::cout << "  Alice's decryption share:        " << std::setw(10) << reveal1Duration.count() << " us" << std::endl;
    std::cout << "  Bob's decryption share:          " << std::setw(10) << reveal2Duration.count() << " us" << std::endl;
    std::cout << "  Combine shares & reveal:         " << std::setw(10) << combineDuration.count() << " us" << std::endl;
    std::cout << "  ----------------------------------------" << std::endl;
    std::cout << "  Total time:                      " << std::setw(10) << totalDuration.count() << " ms" << std::endl;

    std::cout << std::endl;
    std::cout << "Size Metrics:" << std::endl;
    std::cout << "  Deck size (encrypted):           " << std::setw(10) << deckSize << " bytes" << std::endl;
    std::cout << "  Deck size per card:              " << std::setw(10) << (deckSize / 52) << " bytes" << std::endl;

    std::cout << std::endl;
    std::cout << "=== Protocol Summary ===" << std::endl;
    std::cout << "1. Alice and Bob generated independent key pairs" << std::endl;
    std::cout << "2. Alice encrypted 52 cards and shuffled them" << std::endl;
    std::cout << "3. Bob re-encrypted and shuffled" << std::endl;
    std::cout << "4. Both players now hold re-encrypted cards" << std::endl;
    std::cout << "5. Neither knows the card order alone" << std::endl;
    std::cout << "6. Cards were cooperatively revealed using threshold decryption" << std::endl;

    return 0;
}

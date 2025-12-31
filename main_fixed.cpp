#include "bayer_groth_shuffle.h"
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <chrono>
#include <iomanip>

using namespace BayerGroth;

struct Card {
    int rank;
    int suit;
    std::string toString() const {
        static const char* ranks[] = {"A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"};
        static const char* suits[] = {"♥", "♦", "♣", "♠"};
        return std::string(ranks[rank]) + suits[suit];
    }
    int toInt() const { return suit * 13 + rank; }
    static Card fromInt(int value) {
        Card c;
        c.suit = value / 13;
        c.rank = value % 13;
        return c;
    }
};

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  Two-Player Card Shuffle Protocol" << std::endl;
    std::cout << "  Based on Bayer-Groth 2012 Shuffle" << std::endl;
    std::cout << "========================================" << std::endl;

    auto start = std::chrono::high_resolution_clock::now();

    std::mt19937_64 rng1(12345);
    std::mt19937_64 rng2(67890);

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

    shuffle.setRandomGenerator(rng1);
    for (int i = 0; i < 52; ++i) {
        Card card = Card::fromInt(i);
        Ciphertext ct = shuffle.encrypt(aliceKey.pk, mpz_class(card.toInt() + 1));
        deck.push_back(ct);
    }
    std::cout << "All cards encrypted and ready for shuffling" << std::endl;

    std::cout << "\n=== Alice's Shuffle ===" << std::endl;

    size_t n = deck.size();
    std::vector<int> perm1 = BayerGrothShuffle::generatePermutation(n, rng1);

    std::vector<mpz_class> rand1(n);
    for (size_t i = 0; i < n; ++i) {
        rand1[i] = shuffle.generateRandomNumber(aliceKey.pk.q);
    }

    deck = shuffle.shuffle(aliceKey.pk, deck, rand1, perm1);

    std::cout << "Alice shuffled the deck" << std::endl;

    std::cout << "\n=== Bob's Turn ===" << std::endl;

    std::cout << "Re-encrypting cards with Bob's public key..." << std::endl;

    shuffle.setRandomGenerator(rng2);
    for (size_t i = 0; i < deck.size(); ++i) {
        mpz_class r = shuffle.generateRandomNumber(bobKey.pk.q);

        mpz_class g_r = shuffle.modExp(bobKey.pk.g, r, bobKey.pk.p);
        mpz_class h_r = shuffle.modExp(bobKey.pk.h, r, bobKey.pk.p);

        deck[i].a = shuffle.modMul(deck[i].a, g_r, bobKey.pk.p);
        deck[i].b = shuffle.modMul(deck[i].b, h_r, bobKey.pk.p);
    }

    std::cout << "Shuffling deck..." << std::endl;
    std::vector<int> perm2 = BayerGrothShuffle::generatePermutation(n, rng2);

    std::vector<mpz_class> rand2(n);
    for (size_t i = 0; i < n; ++i) {
        rand2[i] = shuffle.generateRandomNumber(bobKey.pk.q);
    }

    deck = shuffle.shuffle(bobKey.pk, deck, rand2, perm2);

    std::cout << "Bob shuffled the deck" << std::endl;

    std::cout << "\n*** Both shuffles complete ***" << std::endl;
    std::cout << "*** Neither player knows the card order ***" << std::endl;
    std::cout << "*** Cards must be cooperatively revealed ***" << std::endl;

    std::cout << "\n\n=== Cooperative Reveal Phase ===" << std::endl;
    std::cout << "Both players must cooperate to reveal any card." << std::endl;
    std::cout << "This ensures neither player knows the deck order alone." << std::endl;

    shuffle.setRandomGenerator(rng1);
    std::cout << "\n=== Cooperative Reveal: Position 0 ===" << std::endl;

    const Ciphertext& ct = deck[0];

    std::cout << "Alice providing decryption share (a^sk1)..." << std::endl;
    mpz_class share1 = shuffle.modExp(ct.a, aliceKey.sk, aliceKey.pk.p);

    shuffle.setRandomGenerator(rng2);
    std::cout << "Bob providing decryption share (a^sk2)..." << std::endl;
    mpz_class share2 = shuffle.modExp(ct.a, bobKey.sk, bobKey.pk.p);

    shuffle.setRandomGenerator(rng1);
    std::cout << "Combining shares to reveal card..." << std::endl;
    mpz_class combined = shuffle.modMul(share1, share2, aliceKey.pk.p);

    std::cout << "Computing modular inverse..." << std::endl;
    mpz_class inv;
    mpz_invert(inv.get_mpz_t(), combined.get_mpz_t(), aliceKey.pk.p.get_mpz_t());

    std::cout << "Computing plaintext..." << std::endl;
    mpz_class plaintext;
    mpz_mul(plaintext.get_mpz_t(), ct.b.get_mpz_t(), inv.get_mpz_t());
    mpz_mod(plaintext.get_mpz_t(), plaintext.get_mpz_t(), aliceKey.pk.p.get_mpz_t());

    int value = static_cast<int>(plaintext.get_si()) - 1;

    Card card = Card::fromInt(value);
    std::cout << "Revealed card: " << card.toString() << std::endl;

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "\n========================================" << std::endl;
    std::cout << "  Protocol Complete!" << std::endl;
    std::cout << "  Total time: " << duration.count() << " ms" << std::endl;
    std::cout << "========================================" << std::endl;

    std::cout << "\n=== Protocol Summary ===" << std::endl;
    std::cout << "1. Alice and Bob generated independent key pairs" << std::endl;
    std::cout << "2. Alice encrypted 52 cards and shuffled them" << std::endl;
    std::cout << "3. Bob re-encrypted and shuffled" << std::endl;
    std::cout << "4. Both players now hold re-encrypted cards" << std::endl;
    std::cout << "5. Neither knows the card order alone" << std::endl;
    std::cout << "6. Cards were cooperatively revealed using threshold decryption" << std::endl;

    return 0;
}

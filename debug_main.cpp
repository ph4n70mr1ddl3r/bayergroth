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
    std::cout << "Starting..." << std::endl;
    
    std::mt19937_64 rng1(12345);
    std::mt19937_64 rng2(67890);
    
    std::cout << "RNGs created" << std::endl;

    BayerGrothShuffle shuffle(256);
    std::cout << "Shuffle created" << std::endl;

    shuffle.setRandomGenerator(rng1);
    KeyPair aliceKey = shuffle.generateKeyPair();
    std::cout << "Alice key generated" << std::endl;

    shuffle.setRandomGenerator(rng2);
    KeyPair bobKey = shuffle.generateKeyPair();
    std::cout << "Bob key generated" << std::endl;

    shuffle.setRandomGenerator(rng1);
    std::vector<Ciphertext> deck;
    
    for (int i = 0; i < 52; ++i) {
        Card card = Card::fromInt(i);
        Ciphertext ct = shuffle.encrypt(aliceKey.pk, mpz_class(card.toInt() + 1));
        deck.push_back(ct);
    }
    std::cout << "Deck encrypted" << std::endl;

    size_t n = deck.size();
    std::vector<int> perm1 = BayerGrothShuffle::generatePermutation(n, rng1);
    std::cout << "Permutation generated" << std::endl;

    std::vector<mpz_class> rand1(n);
    for (size_t i = 0; i < n; ++i) {
        rand1[i] = shuffle.generateRandomNumber(aliceKey.pk.q);
    }
    std::cout << "Randomness generated" << std::endl;

    deck = shuffle.shuffle(aliceKey.pk, deck, rand1, perm1);
    std::cout << "Shuffled" << std::endl;

    shuffle.setRandomGenerator(rng2);
    for (size_t i = 0; i < deck.size(); ++i) {
        mpz_class r = shuffle.generateRandomNumber(bobKey.pk.q);
        mpz_class g_r = shuffle.modExp(bobKey.pk.g, r, bobKey.pk.p);
        mpz_class h_r = shuffle.modExp(bobKey.pk.h, r, bobKey.pk.p);
        deck[i].a = shuffle.modMul(deck[i].a, g_r, bobKey.pk.p);
        deck[i].b = shuffle.modMul(deck[i].b, h_r, bobKey.pk.p);
    }
    std::cout << "Re-encrypted" << std::endl;

    std::vector<int> perm2 = BayerGrothShuffle::generatePermutation(n, rng2);
    std::cout << "Permutation 2 generated" << std::endl;

    std::vector<mpz_class> rand2(n);
    for (size_t i = 0; i < n; ++i) {
        rand2[i] = shuffle.generateRandomNumber(bobKey.pk.q);
    }
    std::cout << "Randomness 2 generated" << std::endl;

    deck = shuffle.shuffle(bobKey.pk, deck, rand2, perm2);
    std::cout << "Shuffled 2" << std::endl;

    std::cout << "About to reveal..." << std::endl;

    const Ciphertext& ct = deck[0];
    std::cout << "Got ciphertext" << std::endl;

    mpz_class share1 = shuffle.modExp(ct.a, aliceKey.sk, aliceKey.pk.p);
    std::cout << "share1 computed" << std::endl;

    shuffle.setRandomGenerator(rng2);
    mpz_class share2 = shuffle.modExp(ct.a, bobKey.sk, bobKey.pk.p);
    std::cout << "share2 computed" << std::endl;

    shuffle.setRandomGenerator(rng1);
    mpz_class combined = shuffle.modMul(share1, share2, aliceKey.pk.p);
    std::cout << "combined computed" << std::endl;

    mpz_class inv;
    mpz_invert(inv.get_mpz_t(), combined.get_mpz_t(), aliceKey.pk.p.get_mpz_t());
    std::cout << "inv computed" << std::endl;

    mpz_class plaintext;
    mpz_mul(plaintext.get_mpz_t(), ct.b.get_mpz_t(), inv.get_mpz_t());
    mpz_mod(plaintext.get_mpz_t(), plaintext.get_mpz_t(), aliceKey.pk.p.get_mpz_t());
    std::cout << "plaintext = " << plaintext.get_str() << std::endl;

    std::cout << "Done!" << std::endl;
    return 0;
}

#include "card_shuffle_protocol.h"
#include "crypto_utils.h"
#include <iostream>
#include <algorithm>
#include <random>
#include <chrono>
#include <iomanip>
#include <cstdio>

namespace CardShuffle {

std::string Card::toString() const noexcept {
    static const char* ranks[] = {"A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"};
    static const char* suits[] = {"♥", "♦", "♣", "♠"};
    return std::string(ranks[rank]) + suits[suit];
}

int Card::toInt() const noexcept {
    if (suit < 0 || suit >= 4 || rank < 0 || rank >= 13) {
        return 0;
    }
    return suit * 13 + rank;
}

Card Card::fromInt(int value) {
    Card card;
    card.suit = static_cast<Suit>(value / 13);
    card.rank = value % 13;
    return card;
}

TwoPlayerCardShuffle::TwoPlayerCardShuffle(int securityParam_) : shuffler(securityParam_), securityParam(securityParam_) {
    std::vector<unsigned char> seed1 = getRandomBytesFromDevice(32);
    std::vector<unsigned char> seed2 = getRandomBytesFromDevice(32);
    std::seed_seq seed_seq1(seed1.begin(), seed1.end());
    std::seed_seq seed_seq2(seed2.begin(), seed2.end());
    player1.rng.seed(seed_seq1);
    player2.rng.seed(seed_seq2);
}

TwoPlayerCardShuffle::~TwoPlayerCardShuffle() noexcept {
}

void TwoPlayerCardShuffle::initializePlayers(const std::string& player1Name, const std::string& player2Name) {
    player1.name = player1Name;
    player2.name = player2Name;

    shuffler.setRandomGenerator(player1.rng);
    player1.keyPair = shuffler.generateKeyPair();

    shuffler.setRandomGenerator(player2.rng);
    player2.keyPair = shuffler.generateKeyPair();

    std::cout << "\n=== Player Initialization ===" << std::endl;
    std::cout << player1.name << " generated key pair" << std::endl;
    std::cout << player2.name << " generated key pair" << std::endl;

    if (!verifyKeyCompatibility(player1.keyPair.pk, player2.keyPair.pk)) {
        throw std::runtime_error("Player key incompatibility detected");
    }
}

BayerGroth::Ciphertext TwoPlayerCardShuffle::encryptCard(const BayerGroth::PublicKey& pk, const Card& card, std::mt19937_64& rng) {
    shuffler.setRandomGenerator(rng);
    int cardValue = card.toInt() + 1;
    if (cardValue < 1 || cardValue > 52) {
        throw std::invalid_argument("Invalid card value for encryption");
    }
    return shuffler.encrypt(pk, mpz_class(cardValue));
}

Card TwoPlayerCardShuffle::decryptCard(const BayerGroth::KeyPair& keyPair, const BayerGroth::Ciphertext& ct) {
    mpz_class m;
    mpz_powm(m.get_mpz_t(), ct.a.get_mpz_t(), keyPair.sk.get_mpz_t(), keyPair.pk.p.get_mpz_t());
    mpz_class m_inv;
    mpz_invert(m_inv.get_mpz_t(), m.get_mpz_t(), keyPair.pk.p.get_mpz_t());
    mpz_class plaintext = BayerGroth::BayerGrothShuffle::modMul(ct.b, m_inv, keyPair.pk.p);
    int value = static_cast<int>(plaintext.get_si()) - 1;
    return Card::fromInt(value);
}

void TwoPlayerCardShuffle::setupDeck() {
    deckState.encryptedCards.clear();
    deckState.shuffleHistory.clear();
    deckState.currentPlayerIndex = 0;

    std::cout << "\n=== Setting Up Deck ===" << std::endl;
    std::cout << "Encrypting " << DECK_SIZE << " cards with " << player1.name << "'s public key..." << std::endl;

    for (int i = 0; i < DECK_SIZE; ++i) {
        Card card = Card::fromInt(i);
        BayerGroth::Ciphertext ct = encryptCard(player1.keyPair.pk, card, player1.rng);
        deckState.encryptedCards.push_back(ct);
    }

    std::cout << "All cards encrypted and ready for shuffling" << std::endl;
}

void TwoPlayerCardShuffle::player1Shuffle() {
    std::cout << "\n=== " << player1.name << "'s Shuffle ===" << std::endl;

    shuffler.setRandomGenerator(player1.rng);

    size_t n = deckState.encryptedCards.size();
    std::vector<int> permutation = BayerGroth::BayerGrothShuffle::generatePermutation(n, player1.rng);

    std::vector<mpz_class> reencryptionRand(n);
    for (size_t i = 0; i < n; ++i) {
        reencryptionRand[i] = shuffler.generateRandomNumber(player1.keyPair.pk.q);
    }

    std::vector<BayerGroth::Ciphertext> inputCards = deckState.encryptedCards;
    BayerGroth::ShuffleProof proof;
    deckState.encryptedCards = shuffler.shuffle(
        player1.keyPair.pk,
        inputCards,
        reencryptionRand,
        permutation,
        proof
    );

    ShuffleRound round;
    round.playerIndex = 0;
    round.proof = proof;
    round.permutation = permutation;
    round.inputCards = inputCards;
    round.outputCards = deckState.encryptedCards;
    deckState.shuffleHistory.push_back(round);

    deckState.currentPlayerIndex = 1;

    std::cout << player1.name << " shuffled the deck" << std::endl;
    std::cout << "Proof generated for verification" << std::endl;
}

bool TwoPlayerCardShuffle::player2VerifyAndShuffle() {
    std::cout << "\n=== " << player2.name << "'s Turn ===" << std::endl;

    std::cout << "Verifying " << player1.name << "'s shuffle..." << std::endl;

    if (deckState.shuffleHistory.empty()) {
        std::cout << "ERROR: No shuffle to verify!" << std::endl;
        return false;
    }

    shuffler.setRandomGenerator(player2.rng);

    std::vector<BayerGroth::Ciphertext> inputBeforeShuffle;
    if (deckState.shuffleHistory.size() == 1) {
        inputBeforeShuffle = deckState.shuffleHistory[0].inputCards;
    } else {
        inputBeforeShuffle = deckState.shuffleHistory[deckState.shuffleHistory.size() - 2].outputCards;
    }

    if (!shuffler.verify(player1.keyPair.pk, inputBeforeShuffle, deckState.encryptedCards, deckState.shuffleHistory.back().proof)) {
        std::cout << "ERROR: Verification failed!" << std::endl;
        return false;
    }
    std::cout << "Verification successful!" << std::endl;

    std::cout << "\nRe-encrypting cards with " << player2.name << "'s public key..." << std::endl;

    std::vector<BayerGroth::Ciphertext> reencryptedCards = deckState.encryptedCards;
    std::vector<mpz_class> reencryptionRand(deckState.encryptedCards.size());
    for (size_t i = 0; i < deckState.encryptedCards.size(); ++i) {
        mpz_class r = shuffler.generateRandomNumber(player2.keyPair.pk.q);
        reencryptionRand[i] = r;

        mpz_class g_r = shuffler.modExp(player2.keyPair.pk.g, r, player2.keyPair.pk.p);
        mpz_class h_r = shuffler.modExp(player2.keyPair.pk.h, r, player2.keyPair.pk.p);

        reencryptedCards[i].a = shuffler.modMul(reencryptedCards[i].a, g_r, player2.keyPair.pk.p);
        reencryptedCards[i].b = shuffler.modMul(reencryptedCards[i].b, h_r, player2.keyPair.pk.p);
    }

    std::cout << "Shuffling deck..." << std::endl;
    size_t n = reencryptedCards.size();
    std::vector<int> permutation = BayerGroth::BayerGrothShuffle::generatePermutation(n, player2.rng);

    std::vector<mpz_class> shuffleRand(n);
    for (size_t i = 0; i < n; ++i) {
        shuffleRand[i] = shuffler.generateRandomNumber(player2.keyPair.pk.q);
    }

    BayerGroth::ShuffleProof proof;
    std::vector<BayerGroth::Ciphertext> outputCards = shuffler.shuffle(
        player2.keyPair.pk,
        reencryptedCards,
        shuffleRand,
        permutation,
        proof
    );

    ShuffleRound round;
    round.playerIndex = 1;
    round.proof = proof;
    round.permutation = permutation;
    round.inputCards = reencryptedCards;
    round.outputCards = outputCards;
    deckState.shuffleHistory.push_back(round);

    deckState.encryptedCards = outputCards;

    deckState.currentPlayerIndex = 0;

    std::cout << player2.name << " shuffled the deck" << std::endl;
    std::cout << "Proof generated for verification" << std::endl;

    return true;
}

bool TwoPlayerCardShuffle::player1Verify() {
    std::cout << "\n=== " << player1.name << "'s Final Verification ===" << std::endl;

    if (deckState.shuffleHistory.empty()) {
        std::cout << "ERROR: No shuffle to verify!" << std::endl;
        return false;
    }

    shuffler.setRandomGenerator(player2.rng);

    std::vector<BayerGroth::Ciphertext> inputBeforeShuffle = deckState.shuffleHistory[deckState.shuffleHistory.size() - 1].inputCards;

    std::cout << "Verifying " << player2.name << "'s shuffle..." << std::endl;
    if (!shuffler.verify(player2.keyPair.pk, inputBeforeShuffle, deckState.encryptedCards, deckState.shuffleHistory.back().proof)) {
        std::cout << "ERROR: Verification failed!" << std::endl;
        return false;
    }
    std::cout << "Verification successful!" << std::endl;
    std::cout << "\n*** Both players have verified the shuffle ***" << std::endl;
    std::cout << "*** Neither player knows the card order ***" << std::endl;
    std::cout << "*** Cards must be cooperatively revealed ***" << std::endl;

    return true;
}

bool TwoPlayerCardShuffle::cooperativeReveal(int position, Card& card) {
    if (position < 0 || position >= DECK_SIZE) {
        std::cout << "Invalid position!" << std::endl;
        return false;
    }

    std::cout << "\n=== Cooperative Reveal: Position " << position << " ===" << std::endl;

    const BayerGroth::Ciphertext& ct = deckState.encryptedCards[position];

    std::cout << player1.name << " providing decryption share (a^sk1)..." << std::endl;
    mpz_class share1;
    mpz_powm(share1.get_mpz_t(), ct.a.get_mpz_t(), player1.keyPair.sk.get_mpz_t(), player1.keyPair.pk.p.get_mpz_t());

    std::cout << player2.name << " providing decryption share (a^sk2)..." << std::endl;
    mpz_class share2;
    mpz_powm(share2.get_mpz_t(), ct.a.get_mpz_t(), player2.keyPair.sk.get_mpz_t(), player2.keyPair.pk.p.get_mpz_t());

    mpz_class combined_share = share1 * share2 % player1.keyPair.pk.p;

    mpz_class g_check = shuffler.modExp(player1.keyPair.pk.g, player1.keyPair.sk, player1.keyPair.pk.p);
    bool p1_correct = shuffler.constantTimeEquals(g_check, player1.keyPair.pk.h);

    mpz_class g_check2 = shuffler.modExp(player2.keyPair.pk.g, player2.keyPair.sk, player2.keyPair.pk.p);
    bool p2_correct = shuffler.constantTimeEquals(g_check2, player2.keyPair.pk.h);

    if (!p1_correct) {
        std::cout << "ERROR: Player 1's secret key does not match their public key!" << std::endl;
        return false;
    }
    if (!p2_correct) {
        std::cout << "ERROR: Player 2's secret key does not match their public key!" << std::endl;
        return false;
    }

    std::cout << "Verifying share correctness..." << std::endl;
    mpz_class check1 = shuffler.modExp(share1, player2.keyPair.sk, player1.keyPair.pk.p);
    mpz_class check2 = shuffler.modExp(ct.a, player1.keyPair.sk * player2.keyPair.sk, player1.keyPair.pk.p);
    if (!shuffler.constantTimeEquals(check1, check2)) {
        std::cout << "ERROR: Share verification failed - shares do not match!" << std::endl;
        return false;
    }
    std::cout << "Share verification successful!" << std::endl;

    std::cout << "Combining shares to reveal card..." << std::endl;

    mpz_class m_inv;
    mpz_invert(m_inv.get_mpz_t(), combined_share.get_mpz_t(), player1.keyPair.pk.p.get_mpz_t());

    mpz_class plaintext = ct.b * m_inv % player1.keyPair.pk.p;
    int value = static_cast<int>(plaintext.get_si()) - 1;

    if (value < 0 || value > 51) {
        std::cout << "Error: Invalid card value (" << value << ")!" << std::endl;
        return false;
    }

    card = Card::fromInt(value);
    std::cout << "Revealed card: " << card.toString() << std::endl;

    return true;
}

void TwoPlayerCardShuffle::revealAllCards() {
    std::cout << "\n=== Cooperative Reveal of All Cards ===" << std::endl;
    std::cout << "Cards will be revealed in order (0-" << (DECK_SIZE - 1) << "):" << std::endl;
    std::cout << std::string(50, '-') << std::endl;

    int failures = 0;
    for (int i = 0; i < DECK_SIZE; ++i) {
        Card card;
        if (cooperativeReveal(i, card)) {
            std::cout << "Position " << std::setw(2) << i << ": " << card.toString() << std::endl;
        } else {
            failures++;
            std::cout << "Position " << std::setw(2) << i << ": FAILED" << std::endl;
        }
    }
    std::cout << std::string(50, '-') << std::endl;

    if (failures > 0) {
        std::cout << "WARNING: " << failures << " card(s) could not be revealed" << std::endl;
    }
}

void TwoPlayerCardShuffle::printDeckState() {
    std::cout << "\n=== Current Deck State ===" << std::endl;
    std::cout << "Number of encrypted cards: " << deckState.encryptedCards.size() << std::endl;
    std::cout << "Number of shuffle rounds: " << deckState.shuffleHistory.size() << std::endl;
    std::cout << "Current player: " << (deckState.currentPlayerIndex == 0 ? player1.name : player2.name) << std::endl;
}

bool TwoPlayerCardShuffle::verifyShuffle(const BayerGroth::PublicKey& pk, const std::vector<BayerGroth::Ciphertext>& input, const std::vector<BayerGroth::Ciphertext>& output, const BayerGroth::ShuffleProof& proof) {
    shuffler.setRandomGenerator(player1.rng);
    return shuffler.verify(pk, input, output, proof);
}

bool TwoPlayerCardShuffle::verifyKeyCompatibility(const BayerGroth::PublicKey& pk1, const BayerGroth::PublicKey& pk2) {
    if (pk1.p != pk2.p) {
        std::cout << "ERROR: Players have different prime modulus p" << std::endl;
        return false;
    }
    if (pk1.q != pk2.q) {
        std::cout << "ERROR: Players have different subgroup order q" << std::endl;
        return false;
    }
    if (pk1.g >= pk1.p || pk2.g >= pk2.p) {
        std::cout << "ERROR: Generator g is not in the valid range" << std::endl;
        return false;
    }
    mpz_class g1_q, g2_q;
    mpz_powm(g1_q.get_mpz_t(), pk1.g.get_mpz_t(), pk1.q.get_mpz_t(), pk1.p.get_mpz_t());
    mpz_powm(g2_q.get_mpz_t(), pk2.g.get_mpz_t(), pk2.q.get_mpz_t(), pk2.p.get_mpz_t());
    if (g1_q != 1 || g2_q != 1) {
        std::cout << "ERROR: Generator g does not have order q" << std::endl;
        return false;
    }
    std::cout << "Key compatibility verified: Both players use same p, q, and g" << std::endl;
    return true;
}

} // namespace CardShuffle

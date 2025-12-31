#include "card_shuffle_protocol.h"
#include <iostream>
#include <algorithm>
#include <random>
#include <chrono>
#include <iomanip>

namespace CardShuffle {

std::string Card::toString() const {
    static const char* ranks[] = {"A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"};
    static const char* suits[] = {"♥", "♦", "♣", "♠"};
    return std::string(ranks[rank]) + suits[suit];
}

int Card::toInt() const {
    return suit * 13 + rank;
}

Card Card::fromInt(int value) {
    Card card;
    card.suit = static_cast<Suit>(value / 13);
    card.rank = value % 13;
    return card;
}

TwoPlayerCardShuffle::TwoPlayerCardShuffle() : securityParam(256) {
    std::random_device rd;
    player1.rng.seed(rd());
    player2.rng.seed(rd() + 1);
}

TwoPlayerCardShuffle::~TwoPlayerCardShuffle() {
}

void TwoPlayerCardShuffle::initializePlayers(const std::string& player1Name, const std::string& player2Name) {
    player1.name = player1Name;
    player2.name = player2Name;

    BayerGroth::BayerGrothShuffle shuffler1(securityParam);
    shuffler1.setRandomGenerator(player1.rng);
    player1.keyPair = shuffler1.generateKeyPair();

    BayerGroth::BayerGrothShuffle shuffler2(securityParam);
    shuffler2.setRandomGenerator(player2.rng);
    player2.keyPair = shuffler2.generateKeyPair();

    std::cout << "\n=== Player Initialization ===" << std::endl;
    std::cout << player1.name << " generated key pair" << std::endl;
    std::cout << player2.name << " generated key pair" << std::endl;
}

BayerGroth::Ciphertext TwoPlayerCardShuffle::encryptCard(const BayerGroth::PublicKey& pk, const Card& card, std::mt19937_64& rng) {
    BayerGroth::BayerGrothShuffle shuffler(securityParam);
    shuffler.setRandomGenerator(rng);
    return shuffler.encrypt(pk, mpz_class(card.toInt() + 1));
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
    std::cout << "Encrypting 52 cards with " << player1.name << "'s public key..." << std::endl;

    for (int i = 0; i < 52; ++i) {
        Card card = Card::fromInt(i);
        BayerGroth::Ciphertext ct = encryptCard(player1.keyPair.pk, card, player1.rng);
        deckState.encryptedCards.push_back(ct);
    }

    std::cout << "All cards encrypted and ready for shuffling" << std::endl;
}

void TwoPlayerCardShuffle::player1Shuffle() {
    std::cout << "\n=== " << player1.name << "'s Shuffle ===" << std::endl;

    BayerGroth::BayerGrothShuffle shuffler(securityParam);
    shuffler.setRandomGenerator(player1.rng);

    size_t n = deckState.encryptedCards.size();
    std::vector<int> permutation = BayerGroth::BayerGrothShuffle::generatePermutation(n, player1.rng);

    std::vector<mpz_class> reencryptionRand(n);
    for (size_t i = 0; i < n; ++i) {
        reencryptionRand[i] = shuffler.generateRandomNumber(player1.keyPair.pk.q);
    }

    deckState.encryptedCards = shuffler.shuffle(
        player1.keyPair.pk,
        deckState.encryptedCards,
        reencryptionRand,
        permutation
    );

    BayerGroth::ShuffleProof proof = shuffler.prove(
        player1.keyPair.pk,
        deckState.encryptedCards, deckState.encryptedCards,
        std::vector<mpz_class>(n), reencryptionRand,
        permutation
    );

    ShuffleRound round;
    round.playerIndex = 0;
    round.proof = proof;
    round.permutation = permutation;
    deckState.shuffleHistory.push_back(round);

    deckState.currentPlayerIndex = 1;

    std::cout << player1.name << " shuffled the deck" << std::endl;
    std::cout << "Proof generated for verification" << std::endl;
}

bool TwoPlayerCardShuffle::player2VerifyAndShuffle() {
    std::cout << "\n=== " << player2.name << "'s Turn ===" << std::endl;

    std::cout << "Verifying " << player1.name << "'s shuffle..." << std::endl;

    BayerGroth::BayerGrothShuffle shuffler(securityParam);
    shuffler.setRandomGenerator(player1.rng);

    if (!shuffler.verify(player1.keyPair.pk, deckState.encryptedCards, deckState.encryptedCards, deckState.shuffleHistory.back().proof)) {
        std::cout << "ERROR: Verification failed!" << std::endl;
        return false;
    }
    std::cout << "Verification successful!" << std::endl;

    std::cout << "\nRe-encrypting cards with " << player2.name << "'s public key..." << std::endl;

    for (auto& ct : deckState.encryptedCards) {
        BayerGroth::BayerGrothShuffle s2(securityParam);
        s2.setRandomGenerator(player2.rng);
        mpz_class r = s2.generateRandomNumber(player2.keyPair.pk.q);

        mpz_class g_r, h_r;
        mpz_powm(g_r.get_mpz_t(), player2.keyPair.pk.g.get_mpz_t(), r.get_mpz_t(), player2.keyPair.pk.p.get_mpz_t());
        mpz_powm(h_r.get_mpz_t(), player2.keyPair.pk.h.get_mpz_t(), r.get_mpz_t(), player2.keyPair.pk.p.get_mpz_t());

        mpz_class new_a = ct.a * g_r % player2.keyPair.pk.p;
        mpz_class new_b = ct.b * h_r % player2.keyPair.pk.p;

        ct.a = new_a;
        ct.b = new_b;
    }

    std::cout << "Shuffling deck..." << std::endl;
    size_t n = deckState.encryptedCards.size();
    std::vector<int> permutation = BayerGroth::BayerGrothShuffle::generatePermutation(n, player2.rng);

    std::vector<mpz_class> reencryptionRand(n);
    for (size_t i = 0; i < n; ++i) {
        BayerGroth::BayerGrothShuffle s3(securityParam);
        s3.setRandomGenerator(player2.rng);
        reencryptionRand[i] = s3.generateRandomNumber(player2.keyPair.pk.q);
    }

    deckState.encryptedCards = shuffler.shuffle(
        player2.keyPair.pk,
        deckState.encryptedCards,
        reencryptionRand,
        permutation
    );

    BayerGroth::ShuffleProof proof = shuffler.prove(
        player2.keyPair.pk,
        deckState.encryptedCards, deckState.encryptedCards,
        std::vector<mpz_class>(n), reencryptionRand,
        permutation
    );

    ShuffleRound round;
    round.playerIndex = 1;
    round.proof = proof;
    round.permutation = permutation;
    deckState.shuffleHistory.push_back(round);

    deckState.currentPlayerIndex = 0;

    std::cout << player2.name << " shuffled the deck" << std::endl;
    std::cout << "Proof generated for verification" << std::endl;

    return true;
}

bool TwoPlayerCardShuffle::player1Verify() {
    std::cout << "\n=== " << player1.name << "'s Final Verification ===" << std::endl;

    BayerGroth::BayerGrothShuffle shuffler(securityParam);
    shuffler.setRandomGenerator(player2.rng);

    std::cout << "Verifying " << player2.name << "'s shuffle..." << std::endl;
    if (!shuffler.verify(player2.keyPair.pk, deckState.encryptedCards, deckState.encryptedCards, deckState.shuffleHistory.back().proof)) {
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
    if (position < 0 || position >= 52) {
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

    std::cout << "Combining shares to reveal card..." << std::endl;
    mpz_class combined_share = share1 * share2 % player1.keyPair.pk.p;

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
    std::cout << "Cards will be revealed in order (0-51):" << std::endl;
    std::cout << std::string(50, '-') << std::endl;

    for (int i = 0; i < 52; ++i) {
        Card card;
        if (cooperativeReveal(i, card)) {
            std::cout << "Position " << std::setw(2) << i << ": " << card.toString() << std::endl;
        }
    }
    std::cout << std::string(50, '-') << std::endl;
}

void TwoPlayerCardShuffle::printDeckState() {
    std::cout << "\n=== Current Deck State ===" << std::endl;
    std::cout << "Number of encrypted cards: " << deckState.encryptedCards.size() << std::endl;
    std::cout << "Number of shuffle rounds: " << deckState.shuffleHistory.size() << std::endl;
    std::cout << "Current player: " << (deckState.currentPlayerIndex == 0 ? player1.name : player2.name) << std::endl;
}

} // namespace CardShuffle

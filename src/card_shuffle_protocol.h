#ifndef CARD_SHUFFLE_PROTOCOL_H
#define CARD_SHUFFLE_PROTOCOL_H

#include "bayer_groth_shuffle.h"
#include <vector>
#include <string>
#include <random>

namespace CardShuffle {

constexpr int DECK_SIZE = 52;

enum Suit { HEARTS, DIAMONDS, CLUBS, SPADES };

struct Card {
    int rank;
    Suit suit;
    std::string toString() const noexcept;
    int toInt() const noexcept;
    static Card fromInt(int value);
};

struct Player {
    std::string name;
    BayerGroth::KeyPair keyPair;
    std::mt19937_64 rng;
};

struct ShuffleRound {
    int playerIndex;
    BayerGroth::ShuffleProof proof;
    std::vector<int> permutation;
    std::vector<BayerGroth::Ciphertext> inputCards;
    std::vector<BayerGroth::Ciphertext> outputCards;
};

struct DeckState {
    std::vector<BayerGroth::Ciphertext> encryptedCards;
    std::vector<ShuffleRound> shuffleHistory;
    int currentPlayerIndex;
};

class TwoPlayerCardShuffle {
public:
    explicit TwoPlayerCardShuffle(int securityParam = 256);
    ~TwoPlayerCardShuffle() noexcept;

    void initializePlayers(const std::string& player1Name, const std::string& player2Name);
    void setupDeck();
    void player1Shuffle();
    bool player2VerifyAndShuffle();
    bool player1Verify();
    bool cooperativeReveal(int position, Card& card);
    void revealAllCards();
    void printDeckState();

private:
    BayerGroth::BayerGrothShuffle shuffler;
    Player player1;
    Player player2;
    DeckState deckState;

    BayerGroth::Ciphertext encryptCard(const BayerGroth::PublicKey& pk, const Card& card, std::mt19937_64& rng);
    Card decryptCard(const BayerGroth::KeyPair& keyPair, const BayerGroth::Ciphertext& ct);
    bool verifyShuffle(const BayerGroth::PublicKey& pk, const std::vector<BayerGroth::Ciphertext>& input, const std::vector<BayerGroth::Ciphertext>& output, const BayerGroth::ShuffleProof& proof);
    bool verifyKeyCompatibility(const BayerGroth::PublicKey& pk1, const BayerGroth::PublicKey& pk2);
};

} // namespace CardShuffle

#endif // CARD_SHUFFLE_PROTOCOL_H

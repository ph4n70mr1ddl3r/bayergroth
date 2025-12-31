#ifndef CARD_SHUFFLE_PROTOCOL_H
#define CARD_SHUFFLE_PROTOCOL_H

#include "bayer_groth_shuffle.h"
#include <vector>
#include <string>
#include <map>
#include <random>

namespace CardShuffle {

enum Suit { HEARTS, DIAMONDS, CLUBS, SPADES };

struct Card {
    int rank;
    Suit suit;
    std::string toString() const;
    int toInt() const;
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
};

struct DeckState {
    std::vector<BayerGroth::Ciphertext> encryptedCards;
    std::vector<ShuffleRound> shuffleHistory;
    int currentPlayerIndex;
};

class TwoPlayerCardShuffle {
public:
    TwoPlayerCardShuffle();
    ~TwoPlayerCardShuffle();

    void initializePlayers(const std::string& player1Name, const std::string& player2Name);
    void setupDeck();
    void player1Shuffle();
    bool player2VerifyAndShuffle();
    bool player1Verify();
    bool cooperativeReveal(int position, Card& card);
    void revealAllCards();
    void printDeckState();

private:
    Player player1;
    Player player2;
    DeckState deckState;
    int securityParam;

    BayerGroth::Ciphertext encryptCard(const BayerGroth::PublicKey& pk, const Card& card, std::mt19937_64& rng);
    Card decryptCard(const BayerGroth::KeyPair& keyPair, const BayerGroth::Ciphertext& ct);
    bool verifyShuffle(const BayerGroth::PublicKey& pk, const std::vector<BayerGroth::Ciphertext>& input, const std::vector<BayerGroth::Ciphertext>& output, const BayerGroth::ShuffleProof& proof);
};

} // namespace CardShuffle

#endif // CARD_SHUFFLE_PROTOCOL_H

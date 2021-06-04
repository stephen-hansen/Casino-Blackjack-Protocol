/* Stephen Hansen
 * 6/4/2021
 * CS 544
 *
 * server.h
 * Contains many helper methods to help in defining the
 * server program. Also contains many globals, which help
 * with mapping connections to usernames, mapping connections
 * to current table, mapping usernames to passwords, etc.
 * In particular UDP broadcast methods, blackjack logic,
 * account details, player details, table details, and PDU
 * parsing are all handled here.
 *
 * Basic UDP broadcast algorithm sourced from http://cs.baylor.edu/~donahoo/practical/CSockets/code/BroadcastReceiver.c.
 * I extended this as necessary to support finding the server via broadcast.
 *
 * setup_socket is sourced from https://github.com/rpoisel/ssl-echo/blob/master/util_socket.c.
 *
 * All other code is original and is fully mine.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <algorithm>
#include <random>
#include <map>
#include <mutex>
#include <chrono>
#include <thread>
#include <vector>
#include <iostream>

#include "../protocol/dfa.h"
#include "../protocol/pdu.h"

// auth_credentials maps username to password
std::map<std::string, std::string> auth_credentials = {{"foo", "bar"}, {"sph77", "admin"}, {"kain", "itdepends"}};
// conn_to_user maps SSL connection to username
std::map<SSL*, std::string> conn_to_user;
// conn_to_state maps SSL connection to current DFA state
std::map<SSL*, STATE> conn_to_state;

// handle_broadcast runs in a separate thread, on a UDP broadcast message,
// if the message is "CBP" the server responds with the port that CBP is running on.
// Used in the extra credit.
// Basic structure is taken from http://cs.baylor.edu/~donahoo/practical/CSockets/code/BroadcastReceiver.c
void handle_broadcast(std::string port, std::string service_port) {
   int sock;
   struct sockaddr_in broadcastAddr;
   struct sockaddr_in clientAddr;
   socklen_t socklen = sizeof(struct sockaddr_in);
   unsigned short broadcastPort;
   char buffer[256];
   int len;

   // Create a socket to the UDP port 21211 to receive datagrams
   broadcastPort = atoi(port.c_str());
   if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
      fprintf(stderr, "Failure to create broadcast socket.\n");
      exit(EXIT_FAILURE);
   }

   memset(&broadcastAddr, 0, sizeof(broadcastAddr));
   broadcastAddr.sin_family = AF_INET;
   broadcastAddr.sin_addr.s_addr = htonl(INADDR_ANY);
   broadcastAddr.sin_port = htons(broadcastPort);

   // Attempt to bind to the broadcast port
   if (bind(sock, (struct sockaddr *) &broadcastAddr, sizeof(broadcastAddr)) < 0) {
      fprintf(stderr, "Unable to bind to socket.\n");
      exit(EXIT_FAILURE);
   }

   // Loop forever receiving and responding to datagrams
   for (;;) {
      // Attempt to receive a datagram
      if ((len = recvfrom(sock, buffer, 255, 0, (sockaddr *)&clientAddr, &socklen)) < 0) {
         fprintf(stderr, "Unable to receive from socket.\n");
         exit(EXIT_FAILURE);
      }
      buffer[len] = '\0';
      // If the datagram contains "CBP", respond back with the service port
      if (std::string(buffer) == "CBP") {
         // Got a CBP client, send back service port
         ssize_t str_len = service_port.length() + 1;
         if (sendto(sock, service_port.c_str(), str_len, 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr)) != str_len) {
            fprintf(stderr, "Unable to broadcast back to client.\n");
            exit(EXIT_FAILURE);
         }
      }
   }
}

// AccountDetails holds all critical information for a given username "account".
// All usernames map to an AccountDetails for that specific username.
// Here AccountDetails holds a user balance, and uses a mutex lock so that
// the balance is updated correctly if a user is authenticated on multiple
// clients.
class AccountDetails
{
   private:
      std::mutex mtx;
      uint32_t balance;
   public:
      AccountDetails() {
         balance = 0;
      }
      // Return the user's balance
      uint32_t getBalance() {
         return balance;
      }
      // Update the balance by funds (a change in balance). Note that
      // this method is protected by a lock - only one update can be
      // applied at any given time.
      void adjustBalance(int32_t funds) {
         mtx.lock();
         uint32_t new_balance = balance + funds;
         // Check for overflow before applying the change. If there is no overflow, apply the adjustment.
         bool overflow = (((funds < 0) && (new_balance > balance)) || ((funds > 0) && (new_balance < balance)));
         if (!overflow) {
            balance += funds;
         }
         mtx.unlock();
      }
};

// user_info is a map from usernames to AccountDetails* (lock-protected balances).
std::map<std::string, AccountDetails*> user_info;

// PlayerInfo denotes all information critical to a player in a given game.
// Each player (rather, each SSL connection) maintains a PlayerInfo which denotes
// the current round bet, the hand's value, the hand itself, and if the player
// has disconnected. The "quit" bool is important - all updates to a player are
// wrapped around a mutex lock. If the player disconnects at any point, this bool
// ensures that messages are not errorneously written to the player. Likewise, it
// also ensures that the player's state is not updated any further by a game
// on leaving a table.
class PlayerInfo
{
   SSL* connection;
   std::mutex mtx;
   uint32_t bet = 0;
   uint8_t hand_value;
   std::vector<CardPDU*> hand;
   bool quit = false;
   public:
      PlayerInfo(SSL* conn) {
         connection = conn;
      }
      // Set the current round bet to whatever is given.
      void setBet(uint32_t b) {
         mtx.lock();
         bet = b;
         mtx.unlock();
      }
      // Get the bet for the current round
      uint32_t getBet() {
         return bet;
      }
      // Add a card to the player's hand.
      void addCard(CardPDU* c) {
         mtx.lock();
         hand.push_back(c);
         mtx.unlock();
      }
      // Set the value of the player's hand.
      void setValue(uint8_t v) {
         mtx.lock();
         hand_value = v;
         mtx.unlock();
      }
      // Get the player's hand value
      uint8_t getValue() {
         return hand_value;
      }
      // Remove all cards from the player's hand
      void clearHand() {
         mtx.lock();
         hand.clear();
         mtx.unlock();
      }
      // Get the player's hand (list of cards)
      std::vector<CardPDU*> getHand() {
         return hand;
      }
      // Check whether the player is still connected to the game
      bool isConnected() {
         return !quit;
      }
      // Disconnect the player from the game by setting the quit flag to true
      void disconnect() {
         mtx.lock();
         quit = true;
         mtx.unlock();
      }
      // Write the message, stored in buf, with length num,
      // to the player's SSL connection. Fails if the
      // player disconnected.
      void write(const void *buf, int num) {
         mtx.lock();
         // Write only if the player is connected.
         if (!quit) {
            SSL_write(connection, buf, num);
         }
         mtx.unlock();
      }
      // Set the player's current STATE to st, only
      // if the player is connected.
      void setState(STATE st) {
         mtx.lock();
         // Update conn_to_state to st if the player is connected.
         if (!quit) {
            conn_to_state[connection] = st;
         }
         mtx.unlock();
      }
};

// rank_to_values maps card ranks to valuations.
// Each pair represents the soft valuation and hard valuation respectively.
std::map<char, std::pair<uint8_t, uint8_t>> rank_to_values = {
   {'A', {11,1}},
   {'2', {2,2}},
   {'3', {3,3}},
   {'4', {4,4}},
   {'5', {5,5}},
   {'6', {6,6}},
   {'7', {7,7}},
   {'8', {8,8}},
   {'9', {9,9}},
   {'T', {10,10}},
   {'J', {10,10}},
   {'Q', {10,10}},
   {'K', {10,10}},
};

// Get the valuation of a hand, if we treat the
// first ace as having soft value.
uint8_t get_soft_value(std::vector<CardPDU*> hand) {
   bool seen_soft_ace = false;
   uint8_t value = 0;
   for (auto card : hand) { // Go through every card
      char rank = card->getRank();
      if (!seen_soft_ace) { // If we haven't seen an ace, use soft value 
         value += rank_to_values[rank].first;
      } else { // We have seen an ace, so use hard value
         value += rank_to_values[rank].second;
      }
      if (rank == 'A') { // Seen an ace
         seen_soft_ace = true;
      }
   }
   return value;
}

// Get the valuation of a hand, if we treat all
// cards as having hard value.
uint8_t get_hard_value(std::vector<CardPDU*> hand) {
   uint8_t value = 0;
   for (auto card: hand) { // Go through every card
      value += rank_to_values[card->getRank()].second; // Add the hard value
   }
   return value;
}

// Merge the soft value and hard value into one hand value
// based on whether either value busts or not.
uint8_t get_value(uint8_t soft_value, uint8_t hard_value) {
   if (soft_value <= 21) { // Keep soft value if not bust
      return soft_value;
   } else { // Soft value is a bust, use hard value
      return hard_value;
   }
}

// TableDetails holds all information about a blackjack game,
// including settings specified when creating the table,
// a list of players, information about the dealer,
// a map of connections to PlayerInfo*, a buffer to
// populate when writing to clients, and a random
// engine for shuffling the deck. This class uses a mutex
// lock whenever updating any aspect, and is also responsible
// for running a game thread that manages game logic and ensures
// the game is making progress.
class TableDetails
{
   private:
      std::mutex mtx; // mutex lock, used for class updates
      std::vector<SSL*> players; // list of players in the game
      std::vector<SSL*> pending_players; // list of players to add next round
      std::vector<CardPDU*> deck; // deck to draw cards from (for players and dealer)
      std::vector<CardPDU*> dealer_hand; // dealer's current hand
      uint8_t dealer_value = 0; // value of dealer's hand
      std::thread game_thread; // game thread which handles game logic, runs independently
      bool is_running = false; // true if game thread is running, false otherwise
      bool is_available = true; // true if table can be joined, false otherwise
      std::map<SSL*,PlayerInfo*> player_info; // A mapping of SSL connections to PlayerInfo*
      uint8_t max_players = 5; // Maximum number of players (size of players + pending players)
      uint8_t number_decks = 8; // Number of decks to shuffle
      uint8_t payoff_high = 3; // Numerator of payoff ratio
      uint8_t payoff_low = 2; // Denominator of payoff ratio
      uint16_t bet_min = 25; // Minimum allowed bet
      uint16_t bet_max = 1000; // Maximum allowed bet
      bool hit_soft_17 = true; // Whether the dealer hits on soft 17 (false means stand)
      char * write_buffer = (char *)malloc(4096); // A buffer to write messages through
      std::random_device rd {}; // A random device used for shuffling the deck
      std::default_random_engine rng = std::default_random_engine { rd() }; // The random engine used for shuffling
   public:
      TableDetails() {}
      // The below constructor is used when adding a new table to configure the table
      // based off all the possible configuration headers.
      TableDetails(uint8_t max_players_, uint8_t number_decks_, uint8_t payoff_high_,
            uint8_t payoff_low_, uint16_t bet_min_, uint16_t bet_max_, bool hit_soft_17_) :
         max_players(max_players_),
         number_decks(number_decks_),
         payoff_high(payoff_high_),
         payoff_low(payoff_low_),
         bet_min(bet_min_),
         bet_max(bet_max_),
         hit_soft_17(hit_soft_17_) { }
      // On call to destructor, the write buffer is freed.
      ~TableDetails() {
         free(write_buffer);
      }
      // broadcast sends the message to all connected players as an ASCII response (1-1-5)
      void broadcast(std::string message) {
         // Create the broadcast PDU
         char * write_buffer = (char *)malloc(4096);
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(1, 1, 5, message);
         ssize_t len = rpdu->to_bytes(&write_buffer);
         // Send message to every player in the player_info map
         for (auto pi : player_info) {
            pi.second->write(write_buffer, len);
         }
         free(write_buffer);
         delete rpdu;
      }
      // run_blackjack handles the game logic. It ensures that the blackjack game is making
      // progress even if some players fail to submit an action (hit/stand/double). The
      // method runs in a separate thread and uses sleep durations as timeouts. If the
      // timeout elapses without the player finishing (finishing denoted by a change of state
      // to WAIT_FOR_DEALER), then the game just moves the player there automatically and continues.
      // The dealer's actions are automated here and the winnings are broadcast to each player
      // at the end of each round, and then a new round starts.
      // The thread terminates when no players are at the table, to save on processing power.
      void run_blackjack() {
         is_running = true;
         // Loop forever on rounds, until there are no players
         while (players.size() + pending_players.size() > 0) {
            // Move all pending players in
            mtx.lock();
            for (auto player : pending_players) {
               players.push_back(player);
               // Send the player info that the game is starting
               JoinTableResponsePDU* rpdu = new JoinTableResponsePDU(3, 1, 0, to_string());
               ssize_t len = rpdu->to_bytes(&write_buffer);
               player_info[player]->write(write_buffer, len);
               // Move player to ENTER_BETS
               player_info[player]->setState(ENTER_BETS);
            }
            pending_players.clear();
            mtx.unlock();
            broadcast("Accepting bets!\n\n");
            dealer_hand.clear();
            // Round started, wait on bets
            std::this_thread::sleep_for(std::chrono::seconds(15));
            // Okay, moving to WAIT_FOR_TURN
            broadcast("Starting round...\n\n");
            uint8_t number_of_players = 0;
            // Go through all players, move them into the correct states based on bet.
            for (auto player : players) {
               player_info[player]->clearHand(); // Clear hand from previous round
               if (player_info[player]->getBet() > 0) { // Player has made a bet
                  player_info[player]->setState(WAIT_FOR_TURN); // Player will wait for their turn
                  number_of_players += 1;
                  hit(player); // Give the player their first card
               } else {
                  // No bet response from player, issue timeout
                  ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(1, 1, 7, "Timeout elapsed, please wait for next round.\n\n");
                  ssize_t len = rpdu->to_bytes(&write_buffer);
                  player_info[player]->write(write_buffer, len);
                  // Move the player to IN_PROGRESS, they will join next game
                  player_info[player]->setState(IN_PROGRESS);
                  // Put the player back in pending_players, and remove from players
                  mtx.lock();
                  pending_players.push_back(player);
                  players.erase(std::remove(players.begin(), players.end(), player), players.end());
                  mtx.unlock();
               }
            }
            // If there are no players in the current round, just restart and begin a new round
            if (number_of_players == 0) {
               // Immediately start new round
               for (auto player : players) { // Set all players to ENTER_BETS state
                  player_info[player]->setState(ENTER_BETS);
               }
               continue;
            }
            // Get dealer hit (first card, face card)
            hit_dealer();

            // Get second hit per each player
            for (auto player : players) {
               if (player_info[player]->getBet() > 0) {
                  hit(player); // Give all betting players their second card
               }
            }

            // Now to go through each player, get their turn. Giving 30 seconds for actions on each.
            for (auto player : players) {
               if (player_info[player]->getBet() > 0) { // Ensure we only consider players with bets
                  if (player_info[player]->getHand().size() == 2 && player_info[player]->getValue() == 21) { // Check if player has blackjack (value of 21, 2 cards)
                     player_info[player]->setState(WAIT_FOR_DEALER); // Move player immediately to WAIT_FOR_DEALER
                     broadcast("Player " + conn_to_user[player] + " has a natural blackjack! Skipping turn.\n\n");
                  } else {
                     // Player does not have a natural blackjack, start their turn.
                     player_info[player]->setState(TURN);
                     broadcast("It is " + conn_to_user[player] + "'s turn.\n\n");
                     // Send 3-1-2 response to signify new state.
                     ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(3, 1, 2, "It is your turn!\n\n");
                     ssize_t len = rpdu->to_bytes(&write_buffer);
                     player_info[player]->write(write_buffer, len);
                     delete rpdu;
                     // This technically employs a busy wait, albeit it only runs at most 30 times...
                     // Sorry about this. Not experienced with timeout-driven events.
                     for (int k=0; k<30; k++) {
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                        // Quit the timeout if the player is at WAIT_FOR_DEALER or disconnects.
                        if (conn_to_state[player] == WAIT_FOR_DEALER || !(player_info[player]->isConnected())) {
                           break;
                        }
                     }
                     // The player did not end their turn if the state is not WAIT_FOR_DEALER.
                     if (conn_to_state[player] != WAIT_FOR_DEALER) {
                        // Move the player automatically to next state.
                        player_info[player]->setState(WAIT_FOR_DEALER);
                        // Send warning of timeout
                        ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(1, 1, 7, "Timeout elapsed.\n\n");
                        ssize_t len = rpdu->to_bytes(&write_buffer);
                        player_info[player]->write(write_buffer, len);
                     }
                  }
               }
            }
            // Now all players have made their moves
            // Time to play the dealer strategy
            // Keep hitting until you cannot any more
            while (hit_dealer()) {} // Returns false once the dealer's policy tells them to stand (or they bust)
            // Calculate payouts
            for (auto player : players) {
               uint32_t bet = player_info[player]->getBet(); // Get the player's bet
               uint32_t payout = 0; // Amount of funds the player wins
               if (bet > 0) { // Only consider players with positive bet
                  uint8_t value = player_info[player]->getValue();
                  if (value <= 21) { // Player's value is less than or equal to 21, so they did not bust
                     if (dealer_value > 21 || value > dealer_value) { // Dealer bust, or you beat the dealer
                        payout = (bet*payoff_high)/payoff_low; // Multiple bet by payout ratio
                     } else if (dealer_value == value) { // Tie, or beat with blackjack
                        if (value == 21) { // Possibly beat with blackjack
                           if (player_info[player]->getHand().size() == 2 && dealer_hand.size() > 2) { // Player has blackjack, dealer does not
                              payout = (bet*payoff_high)/payoff_low; // Blackjack win
                           } else if (dealer_hand.size() == 2 && player_info[player]->getHand().size() > 2) { // Dealer has blackjack, player does not
                              payout = 0; // Dealer win by blackjack
                           } else {
                              payout = bet; // Tie, return bet
                           }
                        } else {
                           payout = bet; // Tie, return bet
                        }
                     }
                  }
                  // Update balance to payoff
                  player_info[player]->setBet(0); // Clear bet
                  user_info[conn_to_user[player]]->adjustBalance(payout); // Add payout to player balance
                  WinningsResponsePDU* win_pdu = new WinningsResponsePDU(3,1,4,htonl(payout)); // Send payout as winnings, big endian
                  ssize_t len = win_pdu->to_bytes(&write_buffer);
                  player_info[player]->write(write_buffer, len);
               }
            }
            // Dealer done, new round
            for (auto player : players) {
               // Move all players to ENTER_BETS
               player_info[player]->setState(ENTER_BETS);
            }
         }
         // If we get here, there are no players in the room.
         // Thread terminates, is_running set to false.
         is_running = false;
      }
      // Given an SSL* connection, return the PlayerInfo* for that connection.
      PlayerInfo* getPlayerInfo(SSL* conn) {
         return player_info[conn];
      }
      // Convert the table to a std::string. In this case, it
      // converts the table to the settings string based on the BNF grammar
      // from the design document.
      std::string to_string() {
         std::string out = "";
         out += "max-players:";
         out += std::to_string(max_players);
         out += "\nnumber-decks:";
         out += std::to_string(number_decks);
         out += "\npayoff:";
         out += std::to_string(payoff_high);
         out += "-";
         out += std::to_string(payoff_low);
         out += "\nbet-limits:";
         out += std::to_string(bet_min);
         out += "-";
         out += std::to_string(bet_max);
         out += "\nhit-soft-17:";
         if (hit_soft_17) {
            out += "true";
         } else {
            out += "false";
         }
         out += "\n\n";
         return out;
      }
      // Return true if bet amt is in range allowed by table, false otherwise.
      bool betInRange(uint32_t amt) {
         return (amt >= bet_min) && (amt <= bet_max);
      }
      // Add the player's SSL connection to the table. Returns true if the player is successfully added,
      // false otherwise. Also handles response back to player.
      bool add_player(SSL* player) {
         mtx.lock();
         if (!is_available) { // Table is not available, tell player the table is closed
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 4, "Table is being closed.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(player, write_buffer, len);
            mtx.unlock();
            return false;
         }
         if (players.size() + pending_players.size() == max_players) { // Table is full, inform player and return false
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 3, "Table provided is full, try again later.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(player, write_buffer, len);
            mtx.unlock();
            return false;
         }
         player_info[player] = new PlayerInfo(player); // Add player to map of player info
         if (!is_running) { // Player is the first connection to the server
            players.push_back(player);
            // Start the game thread here
            game_thread = std::thread(&TableDetails::run_blackjack,this);
            // Detach the thread so that we don't need to join it
            game_thread.detach();
            // Move player to ENTER_BETS
            conn_to_state[player] = ENTER_BETS;
            // Inform player the game has started via 3-1-0 response
            JoinTableResponsePDU* rpdu = new JoinTableResponsePDU(3, 1, 0, to_string());
            ssize_t len = rpdu->to_bytes(&write_buffer);
            player_info[player]->write(write_buffer, len);
         } else { // Server is running for other players currently
            // Move player to IN_PROGRESS, they will join later
            conn_to_state[player] = IN_PROGRESS;
            pending_players.push_back(player); // Player joins in next round
            broadcast(conn_to_user[player] + " is joining in the next round.\n\n");
            // Inform the player to wait via 1-1-0 response.
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(1, 1, 0, "Game in progress, please wait for next round.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            player_info[player]->write(write_buffer, len);
         }
         mtx.unlock();
         return true;
      }
      // shutdown closes the table. It also kicks out any current players and moves all players
      // back to the ACCOUNT state.
      void shutdown() {
         mtx.lock();
         // First, inform all current players.
         for (auto player : players) {
            PlayerInfo* pi = getPlayerInfo(player);
            // Inform of closure by 4-1-4 response.
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 4, "Table is being closed.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            pi->write(write_buffer, len);
            // Disconnect player from game.
            pi->disconnect();
            // Move player to ACCOUNT state.
            conn_to_state[player] = ACCOUNT;
         }
         // Wipe all players.
         players.clear();
         // Inform all pending players
         for (auto player : pending_players) {
            PlayerInfo* pi = getPlayerInfo(player);
            // Inform of closure by 4-1-4 response
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 4, "Table is being closed.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            pi->write(write_buffer, len);
            // Disconnect player from game.
            pi->disconnect();
            // Move player to ACCOUNT state.
            conn_to_state[player] = ACCOUNT;
         }
         // Wipe all pending players
         pending_players.clear();
         mtx.unlock();
      }
      // remove_player removes the given player connection from the current game.
      // Returns true if successful, false otherwise.
      bool remove_player(SSL* player) {
         bool ret = false;
         mtx.lock();
         // Check if player is in list of current players
         if (std::count(players.begin(), players.end(), player)) {
            // Remove the player, disconnect them
            players.erase(std::remove(players.begin(), players.end(), player), players.end());
            PlayerInfo* pi = getPlayerInfo(player);
            pi->disconnect();
            ret = true;
         } else if (std::count(pending_players.begin(), pending_players.end(), player)) {
            // Player is in pending players, remove them, disconnect
            pending_players.erase(std::remove(pending_players.begin(), pending_players.end(), player), pending_players.end());
            PlayerInfo* pi = getPlayerInfo(player);
            pi->disconnect();
            ret = true;
         }
         mtx.unlock();
         // Tell the players that the player has left
         broadcast(conn_to_user[player] + " has left! Bye!\n\n");
         return ret;
      }
      // init_deck initializes the table's deck with a sorted vector of cards,
      // based on the number of decks for the table
      bool init_deck() {
         std::vector<char> ranks = {'A','2','3','4','5','6','7','8','9','T','J','Q','K'};
         std::vector<char> suits = {'H','C','D','S'};
         std::vector<CardPDU*> cards;
         // Create the deck of cards number_decks time, put into cards
         for (int i=0; i<number_decks; i++) {
            for (auto rank : ranks) {
               for (auto suit : suits) {
                  CardPDU* card = new CardPDU(rank, suit);
                  cards.push_back(card);
               }
            }
         }
         // Shuffle the combined deck
         std::shuffle(std::begin(cards), std::end(cards), rng);
         // Update the table's deck.
         deck = cards;
         return true;
      }
      // hit gives the specified player connection an extra card. The function writes
      // the appropriate response code to the player depending on their new hand value.
      // If dbl is set to true, the player doubles their bet, which will result in a different
      // response code sent to the player. Note that the return value does not indicate success.
      // If hit returns true, the player is still allowed to hit. If hit returns false, the
      // player may not hit again.
      bool hit(SSL* player, bool dbl=false) {
         mtx.lock();
         bool ret = true;
         // Re-init the deck if it is empty
         if (deck.size() == 0) {
            init_deck();
         }
         // Give the player the last card in the deck
         player_info[player]->addCard(deck.back());
         // Remove last card from deck
         deck.pop_back();
         // Compute soft value, hard value, and overall hand value
         std::vector<CardPDU*> player_hand = player_info[player]->getHand();
         uint8_t soft_value = get_soft_value(player_hand);
         uint8_t hard_value = get_hard_value(player_hand);
         uint8_t value = get_value(soft_value, hard_value);
         // Save the hand's value
         player_info[player]->setValue(value);
         // Determine response code (1-1-x)
         uint8_t rc3 = 1; // Default is 1-1-1
         if (dbl) { // Double default is 1-1-3
            rc3 = 3;
         }
         if (value == 21) { // Player has 21
            if (player_hand.size() == 2) { // Player has blackjack
               rc3 = 4; // Return 1-1-4
            } else { // Player has 21 (Not blackjack)
               rc3 = 6; // Return 1-1-6
            }
            ret = false; // Player cannot hit on 21
         } else if (value > 21) { // Player busts
            rc3 = 2; // Return 1-1-2
            ret = false; // Cannot hit on bust
         }
         // Send the card hand response for hit
         CardHandResponsePDU* chr_pdu = new CardHandResponsePDU(1,1,rc3,1,soft_value,hard_value,player_hand);
         ssize_t len = chr_pdu->to_bytes(&write_buffer);
         player_info[player]->write(write_buffer, len);
         mtx.unlock();
         return ret;
      }
      // hit_dealer simulates a hit for the dealer. This method is simulate to hit for the player.
      // The dealer gets a new card and all players are notified of the dealer's new hand.
      // The return value indicates the dealer's policy. If the return value is true, the
      // dealer should hit again. If the return value is false, this is interpreted as
      // the dealer stands.
      bool hit_dealer() {
         mtx.lock();
         bool ret = true;
         // Re-init deck if it is empty
         if (deck.size() == 0) {
            init_deck();
         }
         // Give dealer the last card in deck
         dealer_hand.push_back(deck.back());
         // Remove last card from deck
         deck.pop_back();
         // Calculate soft value, hard value, overall value for dealer hand
         uint8_t soft_value = get_soft_value(dealer_hand);
         uint8_t hard_value = get_hard_value(dealer_hand);
         uint8_t value = get_value(soft_value, hard_value);
         uint8_t rc3 = 1; // Default return code 1-1-1
         // Determine return code
         if (value == 21) { // Dealer has 21
            if (dealer_hand.size() == 2) { // Dealer has blackjack
               rc3 = 4; // Send 1-1-4
            } else { // Dealer has 21 (No blackjack)
               rc3 = 6; // Send 1-1-6
            }
            ret = false; // Do not hit on blackjack
         } else if (value > 21) { // Dealer busts
            rc3 = 2; // Send 1-1-2
            ret = false; // Dealer cannot hit again
         } else if (value >= 18 || hard_value == 17) {
            // Dealer never hits on hard 17, or hard/soft 18 or higher
            ret = false;
         } else if (!hit_soft_17 && soft_value == 17) {
            // Do not hit on soft 17, if hit_soft_17 is false
            ret = false;
         }
         // Store the dealer's hand value
         dealer_value = value;
         // Build the card hand response for dealer
         CardHandResponsePDU* chr_pdu = new CardHandResponsePDU(1,1,rc3,0,soft_value,hard_value,dealer_hand);
         ssize_t len = chr_pdu->to_bytes(&write_buffer);
         // Send dealer's hand to all players
         for (auto player : players) {
            player_info[player]->write(write_buffer, len);
         }
         delete chr_pdu;
         mtx.unlock();
         return ret;
      }
};

// tables_lock is a lock on tables, a global map of IDs to TableDetails*
std::mutex tables_lock;
// next_table_id is a counter which denotes the ID of the next table via AddTable
uint16_t next_table_id = 1;
// tables maps table ID to table when joining or removing a table
std::map<uint16_t, TableDetails*> tables = {{0, new TableDetails()}};
// conn_to_table_id maps a connection to the table the connection is at
std::map<SSL*, uint16_t> conn_to_table_id;

// handle_getbalance sends the player's balance if the PDU is GetBalance.
// Return true if successful, false otherwise.
bool handle_getbalance(PDU* p, SSL* conn) {
   // Attempt to cast to GetBalance
   GetBalancePDU* pdu = dynamic_cast<GetBalancePDU*>(p);
   if (!pdu) { // Not GetBalance
      return false;
   }
   char * write_buffer = (char *)malloc(4096);
   // Send the balance, as big endian. Get it from user_info with the connection's username.
   BalanceResponsePDU* rpdu = new BalanceResponsePDU(2, 0, 3, htonl(user_info[conn_to_user[conn]]->getBalance()));
   ssize_t len = rpdu->to_bytes(&write_buffer);
   SSL_write(conn, write_buffer, len);
   free(write_buffer);
   return true;
}

// handle_updatebalance attempts to update the player balance if the PDU is UpdateBalance.
// Return true if successful, false otherwise.
bool handle_updatebalance(PDU* p, SSL* conn) {
   // Attempt to cast to UpdateBalance
   UpdateBalancePDU* pdu = dynamic_cast<UpdateBalancePDU*>(p);
   if (!pdu) { // Not UpdateBalance
      return false;
   }
   int32_t funds = pdu->getFunds();
   // Adjust the user's balance by the given amount, do this by the username.
   user_info[conn_to_user[conn]]->adjustBalance(funds);
   // Inform the user that the balance has been updated.
   ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(2, 0, 0, "Balance updated.\n\n");
   char * write_buffer = (char *)malloc(4096);
   ssize_t len = rpdu->to_bytes(&write_buffer);
   SSL_write(conn, write_buffer, len);
   free(write_buffer);
   return true;
}

// addtable creates a new table given the std::string settings, and gives
// the table the settings as specified. The string follows the BNF grammar from
// the design document for AddTable. The connection conn is informed of the
// added table.
void addtable(std::string settings, SSL* conn) {
   std::string headers = settings.substr(0, settings.length()-1); // Cut off trailing \n from headers.
   std::string line;
   size_t pos1;
   // These are the default table settings, per the design doc.
   // Used in case some headers are missing.
   uint8_t max_players = 5;
   uint8_t number_decks = 8;
   uint8_t payoff_high = 3;
   uint8_t payoff_low = 2;
   uint16_t bet_min = 25;
   uint16_t bet_max = 1000;
   bool hit_soft_17 = true;
   // Loop over each individual line in the settings.
   while ((pos1 = headers.find("\n")) != std::string::npos) {
      line = headers.substr(0, pos1);
      size_t pos2 = line.find(":");
      // Try to split line on first :. Skip the line otherwise.
      if (pos2 != std::string::npos) {
         // Get header up to :, value after :
         std::string header = line.substr(0, pos2);
         std::string value = line.substr(pos2+1);
         // Match on header
         if (header == "max-players") {
            // Set the max amount of players
            uint8_t val = atoi(value.c_str());
            if (val > 0) {
               max_players = val;
            }
         } else if (header == "number-decks") {
            // Set the number of decks
            uint8_t val = atoi(value.c_str());
            if (val > 0) {
               number_decks = val;
            }
         } else if (header == "payoff") {
            // Set payoff ratio
            size_t pos3 = value.find("-");
            // Attempt to split off -
            if (pos3 != std::string::npos) {
               // v1 is numerator, v2 is denominator
               std::string v1 = value.substr(0, pos3);
               std::string v2 = value.substr(pos3+1);
               uint8_t val1 = atoi(v1.c_str());
               uint8_t val2 = atoi(v2.c_str());
               if (val1 > 0 && val2 > 0) {
                  // Set the payoff ratio if both numbers are positive
                  payoff_high = val1;
                  payoff_low = val2;
               }
            }
         } else if (header == "bet-limits") {
            // Set the bet limits
            size_t pos3 = value.find("-");
            // Attempt to split off -
            if (pos3 != std::string::npos) {
               // v1 is min, v2 is max
               std::string v1 = value.substr(0, pos3);
               std::string v2 = value.substr(pos3+1);
               uint8_t val1 = atoi(v1.c_str());
               uint8_t val2 = atoi(v2.c_str());
               if (val1 > 0 && val2 > 0) {
                  // Set the bet limits if both numbers are positive
                  bet_min = val1;
                  bet_max = val2;
               }
            }
         } else if (header == "hit-soft-17") {
            // Determine whether dealer hits on soft 17
            if (value == "true") {
               hit_soft_17 = true;
            } else if (value == "false") {
               hit_soft_17 = false;
            }
         }
      }
      // erase each line from the headers list once we are done with it
      headers.erase(0, pos1 + 1);
   }
   uint16_t table_id;
   // Create the new table. Lock on tables_lock (so that concurrent adds cannot happen).
   tables_lock.lock();
   // Use the next table ID
   table_id = next_table_id;
   // Assign table details based on the header parsing.
   tables[table_id] = new TableDetails(max_players, number_decks, payoff_high, payoff_low, bet_min, bet_max, hit_soft_17);
   // Update next table ID
   next_table_id += 1;
   tables_lock.unlock();
   // Send the client the new table ID as big endian
   AddTableResponsePDU* rpdu = new AddTableResponsePDU(2, 1, 4, htons(table_id));
   char * write_buffer = (char *)malloc(4096);
   ssize_t len = rpdu->to_bytes(&write_buffer);
   SSL_write(conn, write_buffer, len);
   free(write_buffer);
}

// handle_addtable checks if the PDU is AddTable
// and if so attempts to add a new table based on
// the provided settings. Returns true if successful,
// false otherwise.
bool handle_addtable(PDU* p, SSL* conn) {
   // Attempt to cast to AddTable
   AddTablePDU* pdu = dynamic_cast<AddTablePDU*>(p);
   if (!pdu) { // Not AddTable
      return false;
   }
   // Call addtable with the settings string and connection
   addtable(pdu->getSettings(), conn);
   return true;
}

// leavetable removes the connection conn from the current table that
// the player is at.
void leavetable(SSL* conn) {
   // Lookup player table, find table ID for connection
   uint32_t table_id = conn_to_table_id[conn];
   if (!(tables.find(table_id) == tables.end())) { // Table ID exists.
      tables[table_id]->remove_player(conn); // Remove the player from the table
      conn_to_table_id.erase(conn); // Remove mapping of conn to table ID
      conn_to_state[conn] = ACCOUNT; // Move to ACCOUNT state
      // Inform client by 2-1-5 response
      ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(2, 1, 5, "Left table.\n\n");
      char * write_buffer = (char *)malloc(4096);
      ssize_t len = rpdu->to_bytes(&write_buffer);
      SSL_write(conn, write_buffer, len);
      free(write_buffer);
   }
}

// handle_leavetable checks if the PDU is LeaveTable
// and if so attempts to have the connection leave the
// current table that it is at. Return true if successful,
// false otherwise.
bool handle_leavetable(PDU* p, SSL* conn) {
   // Attempt to cast to LeaveTable
   LeaveTablePDU* pdu = dynamic_cast<LeaveTablePDU*>(p);
   if (!pdu) { // Not LeaveTable
      return false;
   }
   // Call leavetable for the connection.
   leavetable(conn);
   return true;
}

// handle_chat checks if the PDU is Chat
// and if so finds the connection conn's current
// table, broadcasting the chat message to
// everyone at the table. The message is displayed
// as "<username>: <message>". Return true if successful,
// false otherwise.
bool handle_chat(PDU* p, SSL* conn) {
   // Attempt to cast to Chat
   ChatPDU* pdu = dynamic_cast<ChatPDU*>(p);
   if (!pdu) { // Not Chat
      return false;
   }
   // Get the connection's current table ID
   uint32_t table_id = conn_to_table_id[conn];
   if (!(tables.find(table_id) == tables.end())) { // Check that table exists
      // Broadcast to the table the player's username and their message, ending in newline
      tables[table_id]->broadcast(conn_to_user[conn] + ": " + pdu->getMessage() + "\n");
   }
   return true;
}

// handle_hit checks if the PDU is Hit
// and if so has the connection conn hit a new
// card and their current table. Returns true if
// successful, false otherwise.
bool handle_hit(PDU* p, SSL* conn) {
   // Attempt to cast to Hit
   HitPDU* pdu = dynamic_cast<HitPDU*>(p);
   if (!pdu) { // Not Hit
      return false;
   }
   // Get the connection's current table ID
   uint32_t table_id = conn_to_table_id[conn];
   if (tables.find(table_id) == tables.end()) { // Table ID for connection no longer exists
      // Send an error (5-1-0) to connection
      ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Table ID is no longer valid.\n\n");
      char * write_buffer = (char *)malloc(4096);
      ssize_t len = rpdu->to_bytes(&write_buffer);
      SSL_write(conn, write_buffer, len);  
      free(write_buffer);
   } else {
      // Hit for the player at their table
      bool can_continue = tables[table_id]->hit(conn);
      if (can_continue) { // Player can hit again, so keep their state at TURN
         conn_to_state[conn] = TURN;
      } else { // Player cannot hit again, they must wait for dealer
         conn_to_state[conn] = WAIT_FOR_DEALER;
      }
   }
   return true;
}

// handle_doubledown checks if the PDU is DoubleDown
// and if so has the connection conn first double their bet.
// The doubled bet is checked to ensure that it fits within the
// user's balance. Then, the player hits, and is then moved to
// WAIT_FOR_DEALER. Returns true if successful, false otherwise.
// Note here that successful means the PDU parsed successfully,
// not if the request was actually successful (you might
// fail to doubledown if you have no balance).
bool handle_doubledown(PDU* p, SSL* conn) {
   // Attempt to case to DoubleDown
   DoubleDownPDU* pdu = dynamic_cast<DoubleDownPDU*>(p);
   if (!pdu) { // Not DoubleDown
      return false;
   }
   // Get the connection's current table ID
   uint32_t table_id = conn_to_table_id[conn];
   if (tables.find(table_id) == tables.end()) { // Table ID for connection no longer exists
      // Send an error (5-1-0) to connection
      ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Table ID is no longer valid.\n\n");
      char * write_buffer = (char *)malloc(4096);
      ssize_t len = rpdu->to_bytes(&write_buffer);
      SSL_write(conn, write_buffer, len);  
      free(write_buffer);
   } else {
      // Get the player's info at their table.
      PlayerInfo* pi = tables[table_id]->getPlayerInfo(conn);
      // Get the player's original bet
      uint32_t orig_bet = pi->getBet();
      if (orig_bet > user_info[conn_to_user[conn]]->getBalance()) { // Ensure that the second bet fits within the balance
         // Bet does not fit within balance, inform client via 5-1-0
         char * write_buffer = (char *)malloc(4096);
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "You do not have sufficient funds to double down.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(conn, write_buffer, len);
         free(write_buffer);
         // The request failed, but the parse did succeed, so return true
         return true;
      }
      // Double the player's original bet
      pi->setBet(orig_bet*2);
      // Remove the bet again from the balance
      user_info[conn_to_user[conn]]->adjustBalance(-orig_bet);
      // Hit a new card, use true to specify double down response code
      tables[table_id]->hit(conn, true);
      // Set new state to WAIT_FOR_DEALER
      conn_to_state[conn] = WAIT_FOR_DEALER;
   }
   return true;
}

// handle_stand checks if the PDU is Stand
// and if so moves the player's state to WAIT_FOR_DEALER
// essentially ending their turn. The player is informed
// of this succeeding. Returns true if successful and
// false otherwise.
bool handle_stand(PDU* p, SSL* conn) {
   // Attempt to cast to Stand
   StandPDU* pdu = dynamic_cast<StandPDU*>(p);
   if (!pdu) { // Not Stand
      return false;
   }
   // Move player to WAIT_FOR_DEALER
   conn_to_state[conn] = WAIT_FOR_DEALER;
   // Inform player they successfully stand
   ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(2, 1, 0, "You stand.\n\n");
   char * write_buffer = (char *)malloc(4096);
   ssize_t len = rpdu->to_bytes(&write_buffer);
   SSL_write(conn, write_buffer, len);
   free(write_buffer);
   return true;
}

// setup_socket takes a port number, and sets up a TCP listening socket at the given port.
// setup_socket is sourced from https://github.com/rpoisel/ssl-echo/blob/master/util_socket.c
int setup_socket(short port)
{
    struct sockaddr_in serveraddr;
    int tr = -1;
    int socket_listen = -1;

    /* prepare socket */
    // create listening socket
    if ((socket_listen = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Allow re-binding to port
    if (setsockopt(socket_listen, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int))
            == -1)
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons(port);

    // Bind server to listen on socket
    if (bind(socket_listen, (struct sockaddr *) &serveraddr, sizeof(serveraddr))
            < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // Mark the socket as passive
    if (listen(socket_listen, 1024) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    return socket_listen;
}

// parse_pdu_server is the guts of the server PDU parsing,
// this function reads in a PDU from a SSL connection and
// parses it into the appropriate PDU class. The class
// is then returned, for which you should then do a dynamic
// type check on it to figure out what PDU was parsed and
// how it should be handled at the current state. This
// handles converting bytes into a human-readable PDU
// class for the server.
PDU* parse_pdu_server(SSL* ssl) {
   ssize_t rc = 0;
   char header_buf[2];
   Header* header;
   PDU* pdu = NULL;

   // Read in the 2 byte header
   if ((rc = SSL_read(ssl, header_buf, 2)) <= 0) {
      return pdu;
   }
   // Extract category_code, command_code from header
   header = reinterpret_cast<Header*>(header_buf);
   uint8_t category_code = header->category_code;
   uint8_t command_code = header->command_code;
   // Look up the PDU type based on header
   if (category_code == 0) { // General usage
      if (command_code == 0) { // VERSION
         char message_buf[4];
         // Read in the version number
         if ((rc = SSL_read(ssl, message_buf, 4)) <= 0) {
            return pdu;
         }
         // Build a VersionPDU
         uint32_t version = *reinterpret_cast<uint32_t*>(message_buf);
         pdu = new VersionPDU(version);
      } else if (command_code == 1) { // USER
         char message_buf[34];
         int i = 0;
         char c = '\0';
         // Read a string up to terminating newline or 33 characters
         while ((rc = SSL_read(ssl, &c, 1) > 0)) {
            message_buf[i] = c;
            i++;
            if (c == '\n') {
               break;
            } else if (i == 33) {
               break;
            }
         }
         // Successful message ends in \n
         if (c == '\n') {
            // Terminate the message buffer
            message_buf[i] = '\0';
            // Convert to string, create pdu
            pdu = new UserPDU(std::string(message_buf));
         }
      } else if (command_code == 2) { // PASS
         char message_buf[34];
         int i = 0;
         char c = '\0';
         // Read a string up to terminating newline or 33 characters
         while ((rc = SSL_read(ssl, &c, 1) > 0)) {
            message_buf[i] = c;
            i++;
            if (c == '\n') {
               break;
            } else if (i == 33) {
               break;
            }
         }
         // Successful message ends in \n
         if (c == '\n') {
            // Terminate the message buffer
            message_buf[i] = '\0';
            // Convert to string, create pdu
            pdu = new PassPDU(std::string(message_buf));
         }
      } else if (command_code == 3) { // GETBALANCE
         // No additional parsing necessary, build GetBalance
         pdu = new GetBalancePDU();
      } else if (command_code == 4) { // UPDATEBALANCE
         char message_buf[4];
         // Read in the funds
         if ((rc = SSL_read(ssl, message_buf, 4)) <= 0) {
            return pdu;
         }
         // Create an UpdateBalancePDU with the amount of funds
         int32_t funds = *reinterpret_cast<int32_t*>(message_buf);
         pdu = new UpdateBalancePDU(funds);
      } else if (command_code == 5) { // QUIT
         // No additional parsing necessary, build Quit PDU
         pdu = new QuitPDU();
      }
   } else if (category_code == 1) { // Blackjack-commands
      if (command_code == 0) { // GETTABLES
         // No additional parsing necessary, build GetTables PDU
         pdu = new GetTablesPDU();
      } else if (command_code == 1) { // ADDTABLE
         // Parse up to double newline
         char message_buf[1027];
         int i = 0;
         char c = '\0';
         bool saw_newline = false; // Tracks whether previous character is newline
         while ((rc = SSL_read(ssl, &c, 1) > 0)) {
            message_buf[i] = c;
            i++;
            if (c == '\n') {
               if (saw_newline) {
                  break;
               } else {
                  saw_newline = true;
               }
            } else {
               saw_newline = false;
            }

            // Allow at most 1026 characters
            if (i == 1026) {
               break;
            }
         }
         // Successful message ends in \n and saw_newline
         if (c == '\n' && saw_newline) {
            // Terminate the message buffer
            message_buf[i] = '\0';
            // Convert to string, create pdu
            pdu = new AddTablePDU(std::string(message_buf));
         }
      } else if (command_code == 2) { // REMOVETABLE
         char message_buf[2];
         // Read in the table ID
         if ((rc = SSL_read(ssl, message_buf, 2)) <= 0) {
            return pdu;
         }
         // Get table ID, create RemoveTable PDU
         uint16_t tid = *reinterpret_cast<uint16_t*>(message_buf);
         pdu = new RemoveTablePDU(tid);
      } else if (command_code == 3) { // JOINTABLE
         char message_buf[2];
         // Read in the table ID
         if ((rc = SSL_read(ssl, message_buf, 2)) <= 0) {
            return pdu;
         }
         // Get table ID, create JoinTable PDU
         uint16_t tid = *reinterpret_cast<uint16_t*>(message_buf);
         pdu = new JoinTablePDU(tid);
      } else if (command_code == 4) { // LEAVETABLE
         // No additional parsing necessary, create LeaveTable PDU
         pdu = new LeaveTablePDU();
      } else if (command_code == 5) { // BET
         char message_buf[4];
         // Read in the bet amount
         if ((rc = SSL_read(ssl, message_buf, 4)) <= 0) {
            return pdu;
         }
         // Get amount to bet, create Bet PDU
         uint32_t amt = *reinterpret_cast<uint32_t*>(message_buf);
         pdu = new BetPDU(amt);
      } else if (command_code == 7) { // HIT
         // No additional parsing necessary, create Hit PDU
         pdu = new HitPDU();
      } else if (command_code == 8) { // STAND
         // No additional parsing necessary, create Stand PDU
         pdu = new StandPDU();
      } else if (command_code == 9) { // DOUBLEDOWN
         // No additional parsing necessary, create DoubleDown PDU
         pdu = new DoubleDownPDU();
      } else if (command_code == 12) { // CHAT
         char message_buf[130];
         int i = 0;
         char c = '\0';
         // Read up to terminating newline or 129 characters
         while ((rc = SSL_read(ssl, &c, 1) > 0)) {
            message_buf[i] = c;
            i++;
            if (c == '\n') {
               break;
            } else if (i == 129) {
               break;
            }
         }
         // Successful message ends in \n
         if (c == '\n') {
            // Terminate the message buffer
            message_buf[i] = '\0';
            // Convert to string, create pdu
            pdu = new ChatPDU(std::string(message_buf));
         }

      }
   }
   // Return whatever PDU was found. If the PDU fails to be created, returns NULL.
   return pdu;
}


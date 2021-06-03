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

std::map<std::string, std::string> auth_credentials = {{"foo", "bar"}, {"sph77", "admin"}, {"kain", "itdepends"}};
std::map<SSL*, std::string> conn_to_user;
std::map<SSL*, STATE> conn_to_state;

// Basic structure is taken from http://cs.baylor.edu/~donahoo/practical/CSockets/code/BroadcastReceiver.c
void handle_broadcast(std::string port, std::string service_port) {
   int sock;
   struct sockaddr_in broadcastAddr;
   struct sockaddr_in clientAddr;
   socklen_t socklen = sizeof(struct sockaddr_in);
   unsigned short broadcastPort;
   char buffer[256];
   int len;

   broadcastPort = atoi(port.c_str());
   if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
      fprintf(stderr, "Failure to create broadcast socket.\n");
      exit(EXIT_FAILURE);
   }

   memset(&broadcastAddr, 0, sizeof(broadcastAddr));
   broadcastAddr.sin_family = AF_INET;
   broadcastAddr.sin_addr.s_addr = htonl(INADDR_ANY);
   broadcastAddr.sin_port = htons(broadcastPort);

   if (bind(sock, (struct sockaddr *) &broadcastAddr, sizeof(broadcastAddr)) < 0) {
      fprintf(stderr, "Unable to bind to socket.\n");
      exit(EXIT_FAILURE);
   }

   for (;;) {
      if ((len = recvfrom(sock, buffer, 255, 0, (sockaddr *)&clientAddr, &socklen)) < 0) {
         fprintf(stderr, "Unable to receive from socket.\n");
         exit(EXIT_FAILURE);
      }
      buffer[len] = '\0';
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

class AccountDetails
{
   private:
      std::mutex mtx;
      uint32_t balance;
   public:
      AccountDetails() {
         balance = 0;
      }
      uint32_t getBalance() {
         return balance;
      }
      void adjustBalance(int32_t funds) {
         mtx.lock();
         uint32_t new_balance = balance + funds;
         bool overflow = (((funds < 0) && (new_balance > balance)) || ((funds > 0) && (new_balance < balance)));
         if (!overflow) {
            balance += funds;
         }
         mtx.unlock();
      }
};

std::map<std::string, AccountDetails*> user_info;

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
      void setBet(uint32_t b) {
         mtx.lock();
         bet = b;
         mtx.unlock();
      }
      uint32_t getBet() {
         return bet;
      }
      void addCard(CardPDU* c) {
         mtx.lock();
         hand.push_back(c);
         mtx.unlock();
      }
      void setValue(uint8_t v) {
         mtx.lock();
         hand_value = v;
         mtx.unlock();
      }
      uint8_t getValue() {
         return hand_value;
      }
      void clearHand() {
         mtx.lock();
         hand.clear();
         mtx.unlock();
      }
      std::vector<CardPDU*> getHand() {
         return hand;
      }
      bool isConnected() {
         return !quit;
      }
      void disconnect() {
         mtx.lock();
         quit = true;
         mtx.unlock();
      }
      void write(const void *buf, int num) {
         mtx.lock();
         if (!quit) {
            SSL_write(connection, buf, num);
         }
         mtx.unlock();
      }
      void setState(STATE st) {
         mtx.lock();
         if (!quit) {
            conn_to_state[connection] = st;
         }
         mtx.unlock();
      }
};

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

uint8_t get_soft_value(std::vector<CardPDU*> hand) {
   bool seen_soft_ace = false;
   uint8_t value = 0;
   for (auto card : hand) {
      char rank = card->getRank();
      if (!seen_soft_ace) {
         value += rank_to_values[rank].first;
      } else {
         value += rank_to_values[rank].second;
      }
      if (rank == 'A') {
         seen_soft_ace = true;
      }
   }
   return value;
}

uint8_t get_hard_value(std::vector<CardPDU*> hand) {
   uint8_t value = 0;
   for (auto card: hand) {
      value += rank_to_values[card->getRank()].second;
   }
   return value;
}

uint8_t get_value(uint8_t soft_value, uint8_t hard_value) {
   if (soft_value <= 21) {
      return soft_value;
   } else {
      return hard_value;
   }
}

class TableDetails
{
   private:
      std::mutex mtx;
      std::vector<SSL*> players;
      std::vector<SSL*> pending_players;
      std::vector<CardPDU*> deck;
      std::vector<CardPDU*> dealer_hand;
      uint8_t dealer_value = 0;
      std::thread game_thread;
      bool is_running = false;
      bool is_available = true;
      uint8_t player_action_count = 0;
      std::map<SSL*,PlayerInfo*> player_info;
      uint8_t max_players = 5;
      uint8_t number_decks = 8;
      uint8_t payoff_high = 3;
      uint8_t payoff_low = 2;
      uint16_t bet_min = 25;
      uint16_t bet_max = 1000;
      bool hit_soft_17 = true;
      char * write_buffer = (char *)malloc(4096);
      std::random_device rd {};
      std::default_random_engine rng = std::default_random_engine { rd() };
   public:
      TableDetails() {}
      ~TableDetails() {
         free(write_buffer);
      }
      void broadcast(std::string message) {
         char * write_buffer = (char *)malloc(4096);
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(1, 1, 5, message);
         ssize_t len = rpdu->to_bytes(&write_buffer);
         for (auto pi : player_info) {
            pi.second->write(write_buffer, len);
         }
         free(write_buffer);
         delete rpdu;
      }
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
            for (auto player : players) {
               player_info[player]->clearHand();
               if (player_info[player]->getBet() > 0) {
                  player_info[player]->setState(WAIT_FOR_TURN);
                  number_of_players += 1;
                  hit(player);
               } else {
                  ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(1, 1, 7, "Timeout elapsed, please wait for next round.\n\n");
                  ssize_t len = rpdu->to_bytes(&write_buffer);
                  player_info[player]->write(write_buffer, len);
                  player_info[player]->setState(IN_PROGRESS);
                  mtx.lock();
                  pending_players.push_back(player);
                  players.erase(std::remove(players.begin(), players.end(), player), players.end());
                  mtx.unlock();
               }
            }
            if (number_of_players == 0) {
               // Immediately start new round
               for (auto player : players) {
                  player_info[player]->setState(ENTER_BETS);
               }
               continue;
            }
            // Get dealer hit
            hit_dealer();

            // Get second hit
            for (auto player : players) {
               if (player_info[player]->getBet() > 0) {
                  hit(player);
               }
            }

            // Now to go through each player, get their turn. Giving 30 seconds for actions
            for (auto player : players) {
               if (player_info[player]->getBet() > 0) {
                  if (player_info[player]->getHand().size() == 2 && player_info[player]->getValue() == 21) {
                     player_info[player]->setState(WAIT_FOR_DEALER);
                     broadcast("Player " + conn_to_user[player] + " has a natural blackjack! Skipping turn.\n\n");
                  } else {
                     player_info[player]->setState(TURN);
                     broadcast("It is " + conn_to_user[player] + "'s turn.\n\n");
                     ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(3, 1, 2, "It is your turn!\n\n");
                     ssize_t len = rpdu->to_bytes(&write_buffer);
                     player_info[player]->write(write_buffer, len);
                     delete rpdu;
                     // This technically employs a busy wait, albeit it only runs at most 30 times...
                     // Sorry about this. Not experienced with timeout-driven events.
                     for (int k=0; k<30; k++) {
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                        if (conn_to_state[player] == WAIT_FOR_DEALER || !(player_info[player]->isConnected())) {
                           break;
                        }
                     }
                     if (conn_to_state[player] != WAIT_FOR_DEALER) {
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
            while (hit_dealer()) {}
            // Calculate payouts
            for (auto player : players) {
               uint32_t bet = player_info[player]->getBet();
               uint32_t payout = 0;
               if (bet > 0) {
                  uint8_t value = player_info[player]->getValue();
                  if (value <= 21) { // Did not bust
                     if (dealer_value > 21 || value > dealer_value) { // Dealer bust, or you beat the dealer
                        payout = (bet*payoff_high)/payoff_low;
                     } else if (dealer_value == value) { // Tie, or beat with blackjack
                        if (value == 21 && player_info[player]->getHand().size() == 2 &&
                              dealer_hand.size() > 2) {
                           payout = (bet*payoff_high)/payoff_low;
                        } else {
                           payout = bet;
                        }
                     }
                  }
                  // Update balance
                  player_info[player]->setBet(0);
                  user_info[conn_to_user[player]]->adjustBalance(payout);
                  WinningsResponsePDU* win_pdu = new WinningsResponsePDU(3,1,4,htonl(payout));
                  ssize_t len = win_pdu->to_bytes(&write_buffer);
                  player_info[player]->write(write_buffer, len);
               }
            }
            // Dealer done, new round
            for (auto player : players) {
               player_info[player]->setState(ENTER_BETS);
            }
         }
         is_running = false;
      }
      PlayerInfo* getPlayerInfo(SSL* conn) {
         return player_info[conn];
      }
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
      bool betInRange(uint32_t amt) {
         return (amt >= bet_min) && (amt <= bet_max);
      }
      bool add_player(SSL* player) {
         mtx.lock();
         if (!is_available) {
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 4, "Table is being closed.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(player, write_buffer, len);
            mtx.unlock();
            return false;
         }
         if (players.size() + pending_players.size() == max_players) {
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 3, "Table provided is full, try again later.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(player, write_buffer, len);
            mtx.unlock();
            return false;
         }
         player_info[player] = new PlayerInfo(player);
         if (!is_running) {
            players.push_back(player);
            // Start the game thread here
            game_thread = std::thread(&TableDetails::run_blackjack,this);
            conn_to_state[player] = ENTER_BETS;
            JoinTableResponsePDU* rpdu = new JoinTableResponsePDU(3, 1, 0, to_string());
            ssize_t len = rpdu->to_bytes(&write_buffer);
            player_info[player]->write(write_buffer, len);
         } else {
            conn_to_state[player] = IN_PROGRESS;
            pending_players.push_back(player); // Player joins in next round
            broadcast(conn_to_user[player] + " is joining in the next round.\n\n");
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(1, 1, 0, "Game in progress, please wait for next round.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            player_info[player]->write(write_buffer, len);
         }
         mtx.unlock();
         return true;
      }
      void shutdown() {
         mtx.lock();
         for (auto player : players) {
            PlayerInfo* pi = getPlayerInfo(player);
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 4, "Table is being closed.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            pi->write(write_buffer, len);
            pi->disconnect();
            conn_to_state[player] = ACCOUNT;
         }
         players.clear();
         for (auto player : pending_players) {
            PlayerInfo* pi = getPlayerInfo(player);
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 4, "Table is being closed.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            pi->write(write_buffer, len);
            pi->disconnect();
            conn_to_state[player] = ACCOUNT;
         }
         pending_players.clear();
         mtx.unlock();
      }
      bool remove_player(SSL* player) {
         bool ret = false;
         mtx.lock();
         if (std::count(players.begin(), players.end(), player)) {
            players.erase(std::remove(players.begin(), players.end(), player), players.end());
            PlayerInfo* pi = getPlayerInfo(player);
            pi->disconnect();
            ret = true;
         } else if (std::count(pending_players.begin(), pending_players.end(), player)) {
            pending_players.erase(std::remove(pending_players.begin(), pending_players.end(), player), pending_players.end());
            PlayerInfo* pi = getPlayerInfo(player);
            pi->disconnect();
            ret = true;
         }
         mtx.unlock();
         broadcast(conn_to_user[player] + " has left! Bye!\n\n");
         // TODO shutdown thread if no one playing 
         return ret;
      }
      bool init_deck() {
         std::vector<char> ranks = {'A','2','3','4','5','6','7','8','9','T','J','Q','K'};
         std::vector<char> suits = {'H','C','D','S'};
         std::vector<CardPDU*> cards;
         for (int i=0; i<number_decks; i++) {
            for (auto rank : ranks) {
               for (auto suit : suits) {
                  CardPDU* card = new CardPDU(rank, suit);
                  cards.push_back(card);
               }
            }
         }
         std::shuffle(std::begin(cards), std::end(cards), rng);
         deck = cards;
         return true;
      }
      bool hit(SSL* player, bool dbl=false) {
         mtx.lock();
         bool ret = true;
         if (deck.size() == 0) {
            init_deck();
         }
         player_info[player]->addCard(deck.back());
         deck.pop_back();
         std::vector<CardPDU*> player_hand = player_info[player]->getHand();
         uint8_t soft_value = get_soft_value(player_hand);
         uint8_t hard_value = get_hard_value(player_hand);
         uint8_t value = get_value(soft_value, hard_value);
         player_info[player]->setValue(value);
         uint8_t rc3 = 1;
         if (dbl) {
            rc3 = 3;
         }
         if (value == 21) {
            if (player_hand.size() == 2) {
               rc3 = 4;
            } else {
               rc3 = 6;
            }
            ret = false;
         } else if (value > 21) {
            rc3 = 2;
            ret = false;
         }
         CardHandResponsePDU* chr_pdu = new CardHandResponsePDU(1,1,rc3,1,soft_value,hard_value,player_hand);
         ssize_t len = chr_pdu->to_bytes(&write_buffer);
         player_info[player]->write(write_buffer, len);
         mtx.unlock();
         return ret;
      }
      bool hit_dealer() {
         mtx.lock();
         bool ret = true;
         if (deck.size() == 0) {
            init_deck();
         }
         dealer_hand.push_back(deck.back());
         deck.pop_back();
         uint8_t soft_value = get_soft_value(dealer_hand);
         uint8_t hard_value = get_hard_value(dealer_hand);
         uint8_t value = get_value(soft_value, hard_value);
         uint8_t rc3 = 1;
         if (value == 21) {
            if (dealer_hand.size() == 2) {
               rc3 = 4;
            } else {
               rc3 = 6;
            }
            ret = false;
         } else if (value > 21) {
            rc3 = 2;
            ret = false;
         } else if (value >= 18 || hard_value == 17) {
            // Dealer never hits on hard 17, or hard/soft 18 or higher
            ret = false;
         } else if (!hit_soft_17 && soft_value == 17) {
            // Do not hit again on the soft 17
            ret = false;
         }
         dealer_value = value;
         CardHandResponsePDU* chr_pdu = new CardHandResponsePDU(1,1,rc3,0,soft_value,hard_value,dealer_hand);
         ssize_t len = chr_pdu->to_bytes(&write_buffer);
         for (auto player : players) {
            player_info[player]->write(write_buffer, len);
         }
         delete chr_pdu;
         mtx.unlock();
         return ret;
      }
};

std::map<uint16_t, TableDetails*> tables = {{0, new TableDetails()}}; 
std::map<SSL*, uint16_t> conn_to_table_id;

bool handle_getbalance(PDU* p, SSL* conn) {
   GetBalancePDU* pdu = dynamic_cast<GetBalancePDU*>(p);
   if (!pdu) {
      return false;
   }
   char * write_buffer = (char *)malloc(4096);
   // Send the balance
   BalanceResponsePDU* rpdu = new BalanceResponsePDU(2, 0, 3, htonl(user_info[conn_to_user[conn]]->getBalance()));
   ssize_t len = rpdu->to_bytes(&write_buffer);
   SSL_write(conn, write_buffer, len);
   free(write_buffer);
   return true;
}

bool handle_updatebalance(PDU* p, SSL* conn) {
   UpdateBalancePDU* pdu = dynamic_cast<UpdateBalancePDU*>(p);
   if (!pdu) {
      return false;
   }
   int32_t funds = pdu->getFunds();
   user_info[conn_to_user[conn]]->adjustBalance(funds);
   ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(2, 0, 0, "Balance updated.\n\n");
   char * write_buffer = (char *)malloc(4096);
   ssize_t len = rpdu->to_bytes(&write_buffer);
   SSL_write(conn, write_buffer, len);
   free(write_buffer);
   return true;
}

void leavetable(SSL* conn) {
   uint32_t table_id = conn_to_table_id[conn];
   if (!(tables.find(table_id) == tables.end())) {
      tables[table_id]->remove_player(conn);
      conn_to_table_id.erase(conn);
      conn_to_state[conn] = ACCOUNT;
      ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(2, 1, 5, "Left table.\n\n");
      char * write_buffer = (char *)malloc(4096);
      ssize_t len = rpdu->to_bytes(&write_buffer);
      SSL_write(conn, write_buffer, len);
      free(write_buffer);
   }
}

bool handle_leavetable(PDU* p, SSL* conn) {
   LeaveTablePDU* pdu = dynamic_cast<LeaveTablePDU*>(p);
   if (!pdu) {
      return false;
   }
   leavetable(conn);
   return true;
}

bool handle_chat(PDU* p, SSL* conn) {
   ChatPDU* pdu = dynamic_cast<ChatPDU*>(p);
   if (!pdu) {
      return false;
   }
   uint32_t table_id = conn_to_table_id[conn];
   if (!(tables.find(table_id) == tables.end())) {
      tables[table_id]->broadcast(conn_to_user[conn] + ": " + pdu->getMessage() + "\n");
   }
   return true;
}

bool handle_hit(PDU* p, SSL* conn) {
   HitPDU* pdu = dynamic_cast<HitPDU*>(p);
   if (!pdu) {
      return false;
   }
   uint32_t table_id = conn_to_table_id[conn];
   if (tables.find(table_id) == tables.end()) {
      ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Table ID is no longer valid.\n\n");
      char * write_buffer = (char *)malloc(4096);
      ssize_t len = rpdu->to_bytes(&write_buffer);
      SSL_write(conn, write_buffer, len);  
      free(write_buffer);
   } else {
      bool can_continue = tables[table_id]->hit(conn);
      if (can_continue) {
         conn_to_state[conn] = TURN;
      } else {
         conn_to_state[conn] = WAIT_FOR_DEALER;
      }
   }
   return true;
}

bool handle_doubledown(PDU* p, SSL* conn) {
   DoubleDownPDU* pdu = dynamic_cast<DoubleDownPDU*>(p);
   if (!pdu) {
      return false;
   }
   uint32_t table_id = conn_to_table_id[conn];
   if (tables.find(table_id) == tables.end()) {
      ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Table ID is no longer valid.\n\n");
      char * write_buffer = (char *)malloc(4096);
      ssize_t len = rpdu->to_bytes(&write_buffer);
      SSL_write(conn, write_buffer, len);  
      free(write_buffer);
   } else {
      PlayerInfo* pi = tables[table_id]->getPlayerInfo(conn);
      uint32_t orig_bet = pi->getBet();
      if (orig_bet > user_info[conn_to_user[conn]]->getBalance()) {
         char * write_buffer = (char *)malloc(4096);
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "You do not have sufficient funds to double down.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(conn, write_buffer, len);
         free(write_buffer);
         return true;
      }
      pi->setBet(orig_bet*2);
      user_info[conn_to_user[conn]]->adjustBalance(-orig_bet);
      tables[table_id]->hit(conn, true);
      conn_to_state[conn] = WAIT_FOR_DEALER;
   }
   return true;
}

bool handle_stand(PDU* p, SSL* conn) {
   StandPDU* pdu = dynamic_cast<StandPDU*>(p);
   if (!pdu) {
      return false;
   }
   conn_to_state[conn] = WAIT_FOR_DEALER;
   ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(2, 1, 0, "You stand.\n\n");
   char * write_buffer = (char *)malloc(4096);
   ssize_t len = rpdu->to_bytes(&write_buffer);
   SSL_write(conn, write_buffer, len);
   free(write_buffer);
   return true;
}

int setup_socket(short port)
{
    struct sockaddr_in serveraddr;
    int tr = -1;
    int socket_listen = -1;

    /* prepare socket */
    if ((socket_listen = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

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

    if (bind(socket_listen, (struct sockaddr *) &serveraddr, sizeof(serveraddr))
            < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(socket_listen, 1024) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    return socket_listen;
}

PDU* parse_pdu_server(SSL* ssl) {
   ssize_t rc = 0;
   char header_buf[2];
   Header* header;
   PDU* pdu = NULL;

   // Read in the 2 byte header
   if ((rc = SSL_read(ssl, header_buf, 2)) <= 0) {
      return pdu;
   }
   header = reinterpret_cast<Header*>(header_buf);
   uint8_t category_code = header->category_code;
   uint8_t command_code = header->command_code;
   if (category_code == 0) { // General usage
      if (command_code == 0) { // VERSION
         char message_buf[4];
         // Read in the version number
         if ((rc = SSL_read(ssl, message_buf, 4)) <= 0) {
            return pdu;
         }
         uint32_t version = *reinterpret_cast<uint32_t*>(message_buf);
         pdu = new VersionPDU(version);
      } else if (command_code == 1) { // USER
         char message_buf[34];
         int i = 0;
         char c = '\0';
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
         // No additional parsing necessary
         pdu = new GetBalancePDU();
      } else if (command_code == 4) { // UPDATEBALANCE
         char message_buf[4];
         // Read in the funds
         if ((rc = SSL_read(ssl, message_buf, 4)) <= 0) {
            return pdu;
         }
         int32_t funds = *reinterpret_cast<int32_t*>(message_buf);
         pdu = new UpdateBalancePDU(funds);
      } else if (command_code == 5) { // QUIT
         // No additional parsing necessary
         pdu = new QuitPDU();
      }
   } else if (category_code == 1) { // Blackjack
      if (command_code == 0) { // GETTABLES
         // No additional parsing necessary
         pdu = new GetTablesPDU();
      } else if (command_code == 1) { // ADDTABLE
         // TODO
      } else if (command_code == 2) { // REMOVETABLE
         char message_buf[2];
         // Read in the table ID
         if ((rc = SSL_read(ssl, message_buf, 2)) <= 0) {
            return pdu;
         }
         uint16_t tid = *reinterpret_cast<uint16_t*>(message_buf);
         pdu = new RemoveTablePDU(tid);
      } else if (command_code == 3) { // JOINTABLE
         char message_buf[2];
         // Read in the table ID
         if ((rc = SSL_read(ssl, message_buf, 2)) <= 0) {
            return pdu;
         }
         uint16_t tid = *reinterpret_cast<uint16_t*>(message_buf);
         pdu = new JoinTablePDU(tid);
      } else if (command_code == 4) { // LEAVETABLE
         // No additional parsing necessary
         pdu = new LeaveTablePDU();
      } else if (command_code == 5) { // BET
         char message_buf[4];
         // Read in the bet amount
         if ((rc = SSL_read(ssl, message_buf, 4)) <= 0) {
            return pdu;
         }
         uint32_t amt = *reinterpret_cast<uint32_t*>(message_buf);
         pdu = new BetPDU(amt);
      } else if (command_code == 6) { // INSURANCE
         char message_buf[1];
         // Read in whether insurance was accepted
         if ((rc = SSL_read(ssl, message_buf, 1)) <= 0) {
            return pdu;
         }
         uint8_t accept = *reinterpret_cast<uint8_t*>(message_buf);
         pdu = new InsurancePDU(accept);
      } else if (command_code == 7) { // HIT
         // No additional parsing necessary
         pdu = new HitPDU();
      } else if (command_code == 8) { // STAND
         // No additional parsing necessary
         pdu = new StandPDU();
      } else if (command_code == 9) { // DOUBLEDOWN
         // No additional parsing necessary
         pdu = new DoubleDownPDU();
      } else if (command_code == 10) { // SPLIT
         // No additional parsing necessary
         pdu = new SplitPDU();
      } else if (command_code == 11) { // SURRENDER
         // No additional parsing necessary
         pdu = new SurrenderPDU();
      } else if (command_code == 12) { // CHAT
         char message_buf[130];
         int i = 0;
         char c = '\0';
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
   return pdu;
}


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <map>
#include <mutex>
#include <vector>

#include "../protocol/dfa.h"
#include "../protocol/pdu.h"

char * write_buffer = (char *)malloc(4096);
std::map<std::string, std::string> auth_credentials = {{"foo", "bar"}, {"sph77", "admin"}};

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

enum SurrenderOptions {
   NONE,
   LATE,
   EARLY
};

class TableDetails
{
   private:
      std::mutex mtx;
      std::vector<SSL*> players;
      std::vector<SSL*> pending_players;
      uint8_t max_players = 5;
      uint8_t number_decks = 8;
      uint8_t payoff_high = 3;
      uint8_t payoff_low = 2;
      uint16_t bet_min = 25;
      uint16_t bet_max = 1000;
      bool hit_soft_17 = true;
      SurrenderOptions surrender = LATE;
   public:
      TableDetails() {}
      std::string to_string() {
         // TODO fix ascii encoding of numbers
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
         out += "\nsurrender:";
         if (surrender == NONE) {
            out += "none";
         } else if (surrender == LATE) {
            out += "late";
         } else if (surrender == EARLY) {
            out += "early";
         }
         out += "\n\n";
         return out;
      }
};

std::map<SSL*, std::string> conn_to_user;
std::map<SSL*, STATE> conn_to_state;
std::map<std::string, AccountDetails*> user_info;
std::map<uint16_t, TableDetails*> tables = {{0, new TableDetails()}}; 

bool handle_getbalance(PDU* p, SSL* conn) {
   GetBalancePDU* pdu = dynamic_cast<GetBalancePDU*>(p);
   if (!pdu) {
      return false;
   }
   // Send the balance
   BalanceResponsePDU* rpdu = new BalanceResponsePDU(2, 0, 3, htonl(user_info[conn_to_user[conn]]->getBalance()));
   ssize_t len = rpdu->to_bytes(&write_buffer);
   SSL_write(conn, write_buffer, len);
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
   ssize_t len = rpdu->to_bytes(&write_buffer);
   SSL_write(conn, write_buffer, len);
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


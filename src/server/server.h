#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <map>
#include <mutex>
#include <vector>

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

std::map<SSL*, std::string> conn_to_user;
std::map<std::string, AccountDetails*> user_info;

class TableDetails
{
   private:
      std::mutex mtx;
      std::vector<SSL*> players;
      std::vector<SSL*> pending_players;
   public:
      TableDetails() {}
};

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
      } else if (command_code == 1) { // ADDTABLE
      } else if (command_code == 2) { // REMOVETABLE
      } else if (command_code == 3) { // JOINTABLE
      } else if (command_code == 4) { // LEAVETABLE
      } else if (command_code == 5) { // BET
      } else if (command_code == 6) { // INSURANCE
      } else if (command_code == 7) { // HIT
      } else if (command_code == 8) { // STAND
      } else if (command_code == 9) { // DOUBLEDOWN
      } else if (command_code == 10) { // SPLIT
      } else if (command_code == 11) { // SURRENDER
      } else if (command_code == 12) { // CHAT
      }
   }
   return pdu;
}


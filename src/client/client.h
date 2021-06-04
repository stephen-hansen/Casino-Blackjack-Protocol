/* Stephen Hansen
 * 6/4/2021
 * CS 544
 *
 * client.h
 * Contains many helper methods to help in defining the
 * client program. In particular defines methods for supporting
 * UDP broadcast to find the server, PDU parsing from server,
 * state transition handling, and handling server responses
 * by printing important details to the client.
 *
 * Basic UDP broadcast algorithm sourced from http://cs.baylor.edu/~donahoo/practical/CSockets/code/BroadcastSender.c.
 * I extended this as necessary to support finding the server via broadcast.
 *
 * All other code is fully mine.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <iostream>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

#include "../protocol/dfa.h"
#include "../protocol/pdu.h"

// This is the state of the protocol between client and server.
STATE state = VERSION;

// get_udp_datagram reads a datagram from sock, and writes
// the ip/port into buffer. The flag is also set to true on read.
// E.g. given 127.0.0.1 which sends 1234, the buffer is populated
// with 127.0.0.1/1234.
void get_udp_datagram(int sock, char (*buffer)[256], bool * flag) {
   unsigned int len;
   struct sockaddr_storage server;
   socklen_t socklen = sizeof(server);
   std::string ip_port;
   // Attempt to read a datagram
   if ((len = recvfrom(sock, *buffer, 255, 0, (struct sockaddr*)&server, &socklen)) < 0) {
      fprintf(stderr, "Unable to receive data.\n");
      exit(EXIT_FAILURE);
   }
   std::string ip;
   char ip_buffer[256];
   // Get the address as a string, depending on IPv4 or IPv6
   switch (server.ss_family) {
      case AF_INET:
         {
            in_addr sa = ((struct sockaddr_in*)&server)->sin_addr;
            inet_ntop(AF_INET, &sa, ip_buffer, socklen);
         }
         break;
      case AF_INET6:
         {
            in6_addr sa6 = ((struct sockaddr_in6*)&server)->sin6_addr;
            inet_ntop(AF_INET6, &sa6, ip_buffer, socklen);
         }
         break;
   }
   ip = std::string(ip_buffer);
   *buffer[len] = '\0';
   // Combine IP and port into buffer.
   ip_port = ip + "/" + std::string(*buffer);
   strcpy(*buffer, ip_port.c_str());
   *flag = true;
}

// EXTRA CREDIT
// get_blackjack_server loops on sending a UDP datagram to the given IP/port and attempts to read
// a datagram back on a separate thread. The return value of this method is a string that
// contains the IP/port of the nearest CBP service.
// Basic UDP broadcast algorithm taken from http://cs.baylor.edu/~donahoo/practical/CSockets/code/BroadcastSender.c
std::string get_blackjack_server(std::string ip, std::string port) {
   int sock;
   struct sockaddr_in broadcastAddr;
   unsigned short broadcastPort = atoi(port.c_str());
   int broadcastPermission;
   // Set up the UDP socket
   if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
      fprintf(stderr, "socket() failed\n");
      exit(EXIT_FAILURE);
   }
   
   // Enable the socket as BROADCAST
   broadcastPermission = 1;
   if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *)&broadcastPermission, sizeof(broadcastPermission)) < 0) {
      fprintf(stderr, "setsockopt() failed\n");
      exit(EXIT_FAILURE);
   }

   memset(&broadcastAddr, 0, sizeof(broadcastAddr));
   broadcastAddr.sin_family = AF_INET;
   broadcastAddr.sin_addr.s_addr = inet_addr(ip.c_str());
   broadcastAddr.sin_port = htons(broadcastPort);
   char buffer[256];
   memset(buffer, '\0', 256);
   bool received = false;
   // Set up a UDP receiver thread on this broadcast socket.
   std::thread recv_thread(get_udp_datagram, sock, &buffer, &received);
   // Loop until we get a packet back from the server.
   while (!received) {
      // Send a request over broadcast for a CBP server.
      if (sendto(sock, "CBP", 4, 0, (struct sockaddr *)&broadcastAddr, sizeof(broadcastAddr)) != 4) {
         fprintf(stderr, "Unable to send correct amount of bytes.\n");
         exit(EXIT_FAILURE);
      }
      sleep(3);
   }
   // Wait for receiver to terminate
   recv_thread.join();
   // Return the IP/port as a std::string
   return std::string(buffer);
}

// handle_state_transition looks at the three-byte header and
// the current state, and determines what state the client moves into
// next.
// STATEFUL
void handle_state_transition(uint8_t rc1, uint8_t rc2, uint8_t rc3) {
   if (state == ACCOUNT) {
      if (rc1 == 1 && rc2 == 1 && rc3 == 0) { // wait for next round
         state = IN_PROGRESS;
      } else if (rc1 == 3 && rc2 == 1 && rc3 == 0) { // game started
         state = ENTER_BETS;
      }
   } else if (state == IN_PROGRESS) {
      if (rc1 == 3 && rc2 == 1 && rc3 == 0) { // game started
         state = ENTER_BETS;
      } else if (rc1 == 2 && rc2 == 1 && rc3 == 5) { // left game
         state = ACCOUNT;
      } else if (rc1 == 4 && rc2 == 1 && rc3 == 4) { // kicked from table
         state = ACCOUNT;
      }
   } else if (state == ENTER_BETS) {
      if (rc1 == 2 && rc2 == 1 && rc3 == 0) { // bet successfully placed
         state = WAIT_FOR_TURN;
      } else if (rc1 == 1 && rc2 == 1 && rc3 == 7) { // timeout
         state = IN_PROGRESS;
      } else if (rc1 == 2 && rc2 == 1 && rc3 == 5) { // left game
         state = ACCOUNT;
      } else if (rc1 == 4 && rc2 == 1 && rc3 == 4) { // kicked from table
         state = ACCOUNT;
      }
   } else if (state == WAIT_FOR_TURN) {
      if (rc1 == 1 && rc2 == 1 && rc3 == 4) { // got a blackjack
         state = WAIT_FOR_DEALER;
      } else if (rc1 == 3 && rc2 == 1 && rc3 == 2) { // it's the client's turn
         state = TURN;
      } else if (rc1 == 2 && rc2 == 1 && rc3 == 5) { // left game
         state = ACCOUNT;
      } else if (rc1 == 4 && rc2 == 1 && rc3 == 4) { // kicked from table
         state = ACCOUNT;
      }
   } else if (state == TURN) {
      if (rc1 == 2 && rc2 == 1 && rc3 == 0) { // successfully stand
         state = WAIT_FOR_DEALER;
      } else if (rc1 == 1 && rc2 == 1) { // hit/doubledown which led to next state
         if (rc3 == 2 || rc3 == 3 || rc3 == 6 || rc3 == 7) {
            state = WAIT_FOR_DEALER;
         }
      } else if (rc1 == 2 && rc2 == 1 && rc3 == 5) { // left game
         state = ACCOUNT;
      } else if (rc1 == 4 && rc2 == 1 && rc3 == 4) { // kicked from table
         state = ACCOUNT;
      }
   } else if (state == WAIT_FOR_DEALER) {
      if (rc1 == 3 && rc2 == 1 && rc3 == 3) { // game over
         state = ENTER_BETS;
      } else if (rc1 == 3 && rc2 == 1 && rc3 == 4) { // game over
         state = ENTER_BETS;
      } else if (rc1 == 2 && rc2 == 1 && rc3 == 5) { // left game
         state = ACCOUNT;
      } else if (rc1 == 4 && rc2 == 1 && rc3 == 4) { // kicked from table
         state = ACCOUNT;
      }
   }
}

// parse_pdu_client takes an SSL connection and reads
// a PDU from it. The bytes are converted to a PDU* and
// returned to the client. A dynamic type check should then
// be used to handle the PDU.
PDU* parse_pdu_client(SSL* ssl) {
   ssize_t rc = 0;
   char header_buf[3];
   ResponseHeader* header;
   PDU* pdu = NULL;

   // Read in the 3 byte header
   if ((rc = SSL_read(ssl, header_buf, 3)) <= 0) {
      return pdu;
   }
   header = reinterpret_cast<ResponseHeader*>(header_buf);
   uint8_t rc1 = header->reply_code_1;
   uint8_t rc2 = header->reply_code_2;
   uint8_t rc3 = header->reply_code_3;
   if ((rc1 == 2 || rc1 == 5) && rc2 == 0 && rc3 == 1) {
      // Handle version response
      char message_buf[4];
      // Read in the version
      if ((rc = SSL_read(ssl, message_buf, 4)) <= 0) {
         return pdu;
      }
      uint32_t version = *reinterpret_cast<uint32_t*>(message_buf);
      pdu = new VersionResponsePDU(rc1,rc2,rc3,version);
   } else if (rc1 == 2 && rc2 == 0 && rc3 == 3) {
      // Handle balance response
      char message_buf[4];
      // Read in the balance
      if ((rc = SSL_read(ssl, message_buf, 4)) <= 0) {
         return pdu;
      }
      uint32_t balance = *reinterpret_cast<uint32_t*>(message_buf);
      pdu = new BalanceResponsePDU(rc1,rc2,rc3,balance);
   } else if (rc1 == 2 && rc2 == 1 && rc3 == 1) {
      // Handle listtables response
      uint16_t number_of_tables;
      // Read in number of tables
      if ((rc = SSL_read(ssl, &number_of_tables, 2)) <= 0) {
         return pdu;
      }
      number_of_tables = ntohs(number_of_tables);
      std::vector<TabledataPDU*> tabledata;
      // Go through each table
      for (uint16_t i=0; i<number_of_tables; i++) {
         // Read in table ID
         uint16_t tid;
         if ((rc = SSL_read(ssl, &tid, 2)) <= 0) {
            return pdu;
         }
         // Read in table settings
         char table_message_buf[8192];
         int j = 0;
         char c = '\0';
         bool saw_newline = false;
         // Read up to double newline
         while ((rc = SSL_read(ssl, &c, 1) > 0)) {
            table_message_buf[j] = c;
            j++;
            if (c == '\n') {
               if (saw_newline) {
                  break;
               } else {
                  saw_newline = true;
               }
            } else {
               saw_newline = false;
            }

            if (j == 8191) {
               break;
            }
         }
         // Successful message ends in \n and saw_newline
         if (c == '\n' && saw_newline) {
            // Terminate the message buffer
            table_message_buf[j] = '\0';
            // Convert to string, create pdu
            TabledataPDU* tpdu = new TabledataPDU(tid,std::string(table_message_buf));
            // Add to vector
            tabledata.push_back(tpdu);
         }
      }
      pdu = new ListTablesResponsePDU(rc1,rc2,rc3,tabledata);
   } else if (rc1 == 2 && rc2 == 1 && rc3 == 4) {
      // Handle addtable response
      uint16_t table_id;
      // Read in the table id
      if ((rc = SSL_read(ssl, &table_id, 2)) <= 0) {
         return pdu;
      }
      pdu = new AddTableResponsePDU(rc1,rc2,rc3,table_id);
   } else if (rc1 == 3 && rc2 == 1 && rc3 == 0) {
      // Handle jointable response
      char message_buf[8192];
      int i = 0;
      char c = '\0';
      bool saw_newline = false;
      // read up to double newline
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

         if (i == 8191) {
            break;
         }
      }
      // Successful message ends in \n and saw_newline
      if (c == '\n' && saw_newline) {
         // Terminate the message buffer
         message_buf[i] = '\0';
         // Convert to string, create pdu
         pdu = new JoinTableResponsePDU(rc1,rc2,rc3,std::string(message_buf));
      }
   } else if (rc1 == 1 && rc2 == 1 && (rc3 >= 1 && rc3 <= 6 && rc3 != 5)) {
      // Handle card response
      uint8_t holder;
      uint8_t soft_value;
      uint8_t hard_value;
      uint8_t number_of_cards;
      // Read in holder
      if ((rc = SSL_read(ssl, &holder, 1)) <= 0) {
         return pdu;
      }
      // Read in soft_value
      if ((rc = SSL_read(ssl, &soft_value, 1)) <= 0) {
         return pdu;
      }
      // Read in hard_value
      if ((rc = SSL_read(ssl, &hard_value, 1)) <= 0) {
         return pdu;
      }
      // Read in number of cards
      if ((rc = SSL_read(ssl, &number_of_cards, 1)) <= 0) {
         return pdu;
      }
      std::vector<CardPDU*> carddata;
      // Read in each card
      for (uint8_t i=0; i<number_of_cards; i++) {
         // Read in rank
         char rank;
         if ((rc = SSL_read(ssl, &rank, 1)) <= 0) {
            return pdu;
         }
         // Read in suit
         char suit;
         if ((rc = SSL_read(ssl, &suit, 1)) <= 0) {
            return pdu;
         }
         // Add to vector
         carddata.push_back(new CardPDU(rank,suit));
      }
      pdu = new CardHandResponsePDU(rc1,rc2,rc3,holder,soft_value,hard_value,carddata);
   } else if (rc1 == 3 && rc2 == 1 && (rc3 == 3 || rc3 == 4)) {
      // Handle winnings response
      uint32_t winnings;
      // Read in the winnings
      if ((rc = SSL_read(ssl, &winnings, 4)) <= 0) {
         return pdu;
      }
      pdu = new WinningsResponsePDU(rc1,rc2,rc3,winnings);
   } else {
      // Assuming ASCII response
      char message_buf[8192];
      int i = 0;
      char c = '\0';
      bool saw_newline = false;
      // Read up to a double newline
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

         if (i == 8191) {
            break;
         }
      }
      // Successful message ends in \n and saw_newline
      if (c == '\n' && saw_newline) {
         // Terminate the message buffer
         message_buf[i] = '\0';
         // Convert to string, create pdu
         pdu = new ASCIIResponsePDU(rc1,rc2,rc3,std::string(message_buf));
      }
   }
   // State transition handler, run on header values
   // STATEFUL
   handle_state_transition(rc1,rc2,rc3);
   return pdu;
};

// Global bool, stores whether the server connection is active
bool CONNECTED = true;

// listen_to_server continuously parses a PDU, and handles displaying it to the client.
// Runs in a separate thread.
void listen_to_server(SSL* ssl) {
   while (CONNECTED) {
      // Get the next PDU
      PDU * p = parse_pdu_client(ssl);
      // Check for ASCII response, valid at any state
      ASCIIResponsePDU* ar_pdu = dynamic_cast<ASCIIResponsePDU*>(p);
      if (ar_pdu) {
         std::string body = ar_pdu->getBody();
         std::cout << "> " << body.substr(0,body.length()-1);
         continue;
      }
      // Check for VERSION, print server version if matched
      VersionResponsePDU* vr_pdu = dynamic_cast<VersionResponsePDU*>(p);
      if (vr_pdu) {
         std::cout << "> server version=" << vr_pdu->getVersion() << std::endl;
         continue;
      }
      // Check for BALANCE, print balance if matched
      BalanceResponsePDU* br_pdu = dynamic_cast<BalanceResponsePDU*>(p);
      if (br_pdu) {
         std::cout << "> current balance=" << br_pdu->getBalance() << std::endl;
         continue;
      }
      // Check for ListTablesResponse
      ListTablesResponsePDU* ltr_pdu = dynamic_cast<ListTablesResponsePDU*>(p);
      if (ltr_pdu) {
         std::vector<TabledataPDU*> tabledata = ltr_pdu->getTabledata();
         // Go through every table, print the ID and settings
         for (auto data : tabledata) {
            std::cout << "> table ID: " << data->getTableID() << std::endl;
            std::cout << data->getSettings();
         }
         continue;
      }
      // Check for AddTableResponse, print new table ID
      AddTableResponsePDU* atr_pdu = dynamic_cast<AddTableResponsePDU*>(p);
      if (atr_pdu) {
         std::cout << "> added table, table ID=" << atr_pdu->getTableID() << std::endl;
         continue;
      }
      // Check for JoinTableResponse, print joined table settings
      JoinTableResponsePDU* jtr_pdu = dynamic_cast<JoinTableResponsePDU*>(p);
      if (jtr_pdu) {
         std::string settings = jtr_pdu->getSettings();
         std::cout << "> table settings:" << std::endl;
         std::cout << settings;
         continue;
      }
      // Check for CardHandResponse, print details about the hand
      CardHandResponsePDU* chr_pdu = dynamic_cast<CardHandResponsePDU*>(p);
      if (chr_pdu) {
         // Print whether it is your hand or dealer's
         if (chr_pdu->getHolder()) {
            std::cout << "> Your hand:";
         } else {
            std::cout << "> Dealer's hand:";
         }
         std::vector<CardPDU*> cards = chr_pdu->getCards();
         // Print every card
         for (auto card : cards) {
            std::cout << " " << card->getRank() << card->getSuit();
         }
         uint8_t soft_value = chr_pdu->getSoftValue();
         uint8_t hard_value = chr_pdu->getHardValue();
         // Print the card's state
         if (soft_value == 21 && cards.size() == 2) {
            std::cout << " (blackjack)";
         } else if (soft_value == 21 || hard_value == 21) {
            std::cout << " (21)";
         } else if (soft_value < 21 && soft_value != hard_value) {
            std::cout << " (soft " << std::to_string(soft_value) << ")";
         } else if (hard_value < 21) {
            std::cout << " (" << std::to_string(hard_value) << ")";
         } else {
            std::cout << " (bust)";
         }
         std::cout << std::endl;
         continue;
      }
      // Check for winnings, print winnings in last game
      WinningsResponsePDU* wr_pdu = dynamic_cast<WinningsResponsePDU*>(p);
      if (wr_pdu) {
         std::cout << "> winnings=" << wr_pdu->getWinnings() << std::endl;
         continue;
      }
   }
}

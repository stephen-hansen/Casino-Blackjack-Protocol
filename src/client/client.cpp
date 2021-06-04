/* Stephen Hansen
 * 6/4/2021
 * CS 544
 *
 * client.cpp
 * Contains the main method for the CBP client. Also includes many
 * helper methods to establish the SSL connection.
 *
 * SSL connection details are sourced from https://gist.github.com/vedantroy/d2b99d774484cf4ea5165b200888e414.
 * I have made some adjustments to the code after reviewing it, but this provided the framework for
 * establishing an SSL connection via OpenSSL.
 *
 * All other code is fully mine.
 */

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <sstream>
#include <iterator>
#include <algorithm>
#include <string>
#include <thread>
#include <vector>

#include "client.h"

const int ERROR_STATUS = -1;

// InitSSL_CTX establishes an SSL_CTX and returns it.
SSL_CTX *InitSSL_CTX(void)
{
   const SSL_METHOD *method = TLS_client_method(); /* Create new client-method instance */
   SSL_CTX *ctx = SSL_CTX_new(method);

   if (ctx == nullptr)
   {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
   }
   return ctx;
}

// OpenConnection establishes a TCP connection to the given hostname/port, returns
// the socket integer if successful.
int OpenConnection(const char *hostname, const char *port)
{
   struct addrinfo hints = {0}, *addrs;
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_protocol = IPPROTO_TCP; // Set up a TCP socket

   // Attempt to get address info for given hostname/ip and port.
   // CLIENT
   const int status = getaddrinfo(hostname, port, &hints, &addrs);
   if (status != 0)
   {
      fprintf(stderr, "%s: %s\n", hostname, gai_strerror(status));
      exit(EXIT_FAILURE);
   }

   // Create a socket and connect to the given address.
   int sfd, err;
   for (struct addrinfo *addr = addrs; addr != nullptr; addr = addr->ai_next)
   {
      sfd = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
      if (sfd == ERROR_STATUS)
      {
         err = errno;
         continue;
      }

      // If connection succeeded, break out of the loop.
      if (connect(sfd, addr->ai_addr, addr->ai_addrlen) == 0)
      {
         break;
      }

      err = errno;
      sfd = ERROR_STATUS;
      close(sfd);
   }

   freeaddrinfo(addrs);

   if (sfd == ERROR_STATUS)
   {
      fprintf(stderr, "%s: %s\n", hostname, strerror(err));
      exit(EXIT_FAILURE);
   }
   // sfd is the int ID of the socket connection.
   return sfd;
}

// DisplayCerts prints the server certificates at the SSL connection.
void DisplayCerts(SSL *ssl)
{
   X509 *cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
   if (cert != nullptr)
   {
      printf("Server certificates:\n");
      char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
      printf("Subject: %s\n", line);
      delete line;
      line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
      printf("Issuer: %s\n", line);
      delete line;
      X509_free(cert);
   }
   else
   {
      printf("Info: No client certificates configured.\n");
   }
}

// is_number returns true if a std::string contains all numeric characters.
// Source: https://stackoverflow.com/questions/4654636/how-to-determine-if-a-string-is-a-number-with-c
bool is_number(const std::string& s) {
   return !s.empty() && std::find_if(s.begin(), s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}

// This is the main method for the client. Establishes a TLS TCP connection to a CBP server, and
// services commands to the server. Also runs a receiver thread separately to handle server responses.
int main(int argc, char const *argv[])
{
   char * write_buffer = (char*)malloc(4096);
   // Initialize SSL_CTX, SSL connection
   SSL_CTX *ctx = InitSSL_CTX();
   SSL *ssl = SSL_new(ctx);
   if (ssl == nullptr)
   {
      fprintf(stderr, "SSL_new() failed\n");
      exit(EXIT_FAILURE);
   }

   const char * ip_or_hostname;
   // SERVICE
   const char * port_number = "21210"; // Default port number per design
   if (argc == 3) {
      // CLIENT
      ip_or_hostname = argv[1];
      port_number = argv[2];
   } else if (argc == 2) {
      // CLIENT
      // SERVICE
      ip_or_hostname = argv[1];
   } else if (argc == 1) {
      // Service discovery
      std::cout << "Searching for nearest CBP server..." << std::endl;
      // Broadcast to port 21211 to all devices in local network
      std::string ip_port = get_blackjack_server("255.255.255.255", "21211");
      size_t colon_loc = ip_port.find('/');
      // Extract ip/hostname, port from UDP response
      ip_or_hostname = ip_port.substr(0, colon_loc).c_str();
      port_number = ip_port.substr(colon_loc+1).c_str();
   } else {
      fprintf(stderr, "Expected arguments (<hostname/ip>) (<port>)");
      exit(EXIT_FAILURE);
   }

   // Establish the TCP connection
   const int sfd = OpenConnection(ip_or_hostname, port_number);
   // Wrap the TCP connection in SSL.
   SSL_set_fd(ssl, sfd);

   // Try to connect to the TCP connection over SSL.
   const int status = SSL_connect(ssl);
   if (status != 1)
   {
      SSL_get_error(ssl, status);
      ERR_print_errors_fp(stderr); //High probability this doesn't do anything
      fprintf(stderr, "SSL_connect failed with SSL_get_error code %d\n", status);
      exit(EXIT_FAILURE);
   }

   // Print encryption cipher suite, certs
   printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
   DisplayCerts(ssl);
   // Send VERSION on connection (version negotiation)
   uint32_t version = htonl(1); // Version 1, over big endian
   VersionPDU *version_pdu = new VersionPDU(version);
   ssize_t len = version_pdu->to_bytes(&write_buffer);
   SSL_write(ssl, write_buffer, len);
   delete version_pdu;
   // Check that the server sends back a successful version response PDU.
   VersionResponsePDU *vr_pdu = dynamic_cast<VersionResponsePDU*>(parse_pdu_client(ssl));
   if (!vr_pdu || vr_pdu->getReplyCode1() != 2) {
      fprintf(stderr, "Client is not running supported version.\n");
      exit(EXIT_FAILURE);
   }
   bool authenticated = false;
   std::string line;
   // UI
   // Authentication loop
   while (!authenticated) {
      // Get username, send to server
      state = USERNAME;
      std::cout << "Enter username: ";
      std::getline(std::cin, line);
      line.append("\n");
      UserPDU *user_pdu = new UserPDU(line);
      ssize_t len = user_pdu->to_bytes(&write_buffer);
      SSL_write(ssl, write_buffer, len);
      delete user_pdu;
      // Check that the server sends back a non-failure ASCII response
      ASCIIResponsePDU *user_resp = dynamic_cast<ASCIIResponsePDU*>(parse_pdu_client(ssl));
      if (!user_resp || user_resp->getReplyCode1() == 4 || user_resp->getReplyCode1() == 5) {
         fprintf(stderr, "Got an unexpected error from server.\n");
         exit(EXIT_FAILURE);
      }
      // Get password, send to server
      state = PASSWORD;
      std::cout << "Enter password: ";
      std::getline(std::cin, line);
      line.append("\n");
      PassPDU *pass_pdu = new PassPDU(line);
      len = pass_pdu->to_bytes(&write_buffer);
      SSL_write(ssl, write_buffer, len);
      delete pass_pdu;
      // Check that the server sends back a successful password response
      ASCIIResponsePDU *pass_resp = dynamic_cast<ASCIIResponsePDU*>(parse_pdu_client(ssl));
      if (!pass_resp || pass_resp->getReplyCode1() != 2) {
         std::cout << "Invalid username/password" << std::endl;
      } else {
         std::cout << "Successfully authenticated" << std::endl;
         authenticated = true; // Break from loop once authenticated
      }
   }
   state = ACCOUNT;
   // Start up a listening thread
   std::thread listen(listen_to_server,ssl);
   // UI
   std::cout << "Available commands:" << std::endl;
   std::cout << "> balance" << std::endl;
   std::cout << "> adjust <funds>" << std::endl;
   std::cout << "> quit" << std::endl;
   std::cout << "> list" << std::endl;
   std::cout << "> add" << std::endl;
   std::cout << "> remove <table id>" << std::endl;
   std::cout << "> join <table id>" << std::endl;
   std::cout << "> leave" << std::endl;
   std::cout << "> bet <amount>" << std::endl;
   std::cout << "> hit" << std::endl;
   std::cout << "> stand" << std::endl;
   std::cout << "> double" << std::endl;
   std::cout << "> chat <msg>" << std::endl;
   // UI
   // Main command loop driver.
   for (; std::getline(std::cin, line);) {
      // Convert the line entered to tokens, delimited by space
      std::istringstream iss(line);
      std::vector<std::string> tokens;
      std::copy(std::istream_iterator<std::string>(iss), std::istream_iterator<std::string>(), std::back_inserter(tokens));
      if (tokens.size() < 1) {
         // Print help on no tokens
         std::cout << "Available commands:" << std::endl;
         std::cout << "> balance" << std::endl;
         std::cout << "> adjust <funds>" << std::endl;
         std::cout << "> quit" << std::endl;
         std::cout << "> list" << std::endl;
         std::cout << "> add" << std::endl;
         std::cout << "> remove <table id>" << std::endl;
         std::cout << "> join <table id>" << std::endl;
         std::cout << "> leave" << std::endl;
         std::cout << "> bet <amount>" << std::endl;
         std::cout << "> hit" << std::endl;
         std::cout << "> stand" << std::endl;
         std::cout << "> double" << std::endl;
         std::cout << "> chat <msg>" << std::endl;
         continue;
      }
      // Get command, look up what to do
      std::string command = tokens[0];
      // STATEFUL
      if (command == "balance") { // Get the balance
         // Run at any post-authentication state (no state check needed here)
         if (tokens.size() == 1) {
            GetBalancePDU *gb_pdu = new GetBalancePDU();
            ssize_t len = gb_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete gb_pdu;
         } else {
            std::cout << "expected: balance" << std::endl;
         }
      } else if (command == "adjust") { // Adjust the balance
         // Run at any post-authentication state
         if (tokens.size() == 2) {
            std::string funds_str = tokens[1];
            try {
               // Convert funds to int, send over big endian
               int32_t funds = stoi(funds_str);
               UpdateBalancePDU *ub_pdu = new UpdateBalancePDU(htonl(funds));
               ssize_t len = ub_pdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
               delete ub_pdu;
            }
            catch (const std::out_of_range& oor) {
               std::cout << "error, out of range" << std::endl;
            }
         } else {
            std::cout << "expected: adjust <funds>" << std::endl;
         }
      } else if (command == "quit") { // Quit, terminate the connection
         // Run at any post-authentication state
         if (tokens.size() == 1) {
            break; // break the command loop. Quit PDU will be sent before termination.
         } else {
            std::cout << "expected: quit" << std::endl;
         }
      } else if (command == "list") { // List all tables
         if (state != ACCOUNT) { // List only works at ACCOUNT
            std::cout << "Sorry, command not valid at current state." << std::endl;
         } else if (tokens.size() == 1) {
            // Send the GetTables request
            GetTablesPDU *send_pdu = new GetTablesPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: list" << std::endl;
         }
      } else if (command == "add") { // Add a new table
         // Interactive prompt for add settings
         if (state != ACCOUNT) { // Add only works at ACCOUNT
            std::cout << "Sorry, command not valid at current state." << std::endl;
         } else if (tokens.size() == 1) {
            std::string headers;
            // Get number of players, number of decks, payoff ratio, bet limits, if dealer hits on soft 17
            std::cout << "Enter max number of players: ";
            do {
               std::getline(std::cin, line);
            } while (!is_number(line)); // Loop until num players is a number
            headers = "max-players:" + line + "\n";
            std::cout << "Enter number of decks: ";
            do {
               std::getline(std::cin, line);
            } while (!is_number(line)); // Loop until num decks is a number
            headers += "number-decks:" + line + "\n";
            std::cout << "Enter payoff ratio (two numbers, e.g. 3, then 2 for 3-2 payoff): ";
            do {
               std::getline(std::cin, line);
            } while (!is_number(line)); // Loop until first ratio value is a number
            headers += "payoff:" + line;
            std::cout << "Enter second number: ";
            do {
               std::getline(std::cin, line);
            } while (!is_number(line)); // Loop until second ratio value is a number
            headers += "-" + line + "\n";
            std::cout << "Enter minimum bet: ";
            do {
               std::getline(std::cin, line);
            } while (!is_number(line)); // Loop until min bet is a number
            headers += "bet-limits:" + line;
            std::cout << "Enter maximum bet: ";
            do {
               std::getline(std::cin, line);
            } while (!is_number(line)); // Loop until max bet is a number
            headers += "-" + line + "\n";
            std::cout << "Hit soft 17? (yes/[no]): ";
            std::getline(std::cin, line);
            headers += "hit-soft-17:";
            if (line == "yes") { // Matching yes means to set hit-soft-17 as true
               headers += "true";
            } else { // Default any other response as false
               headers += "false";
            }
            // Terminate the headers, send the AddTable command
            headers += "\n\n";
            AddTablePDU *send_pdu = new AddTablePDU(headers);
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: add" << std::endl;
         }
      } else if (command == "remove") { // Remove a table
         if (state != ACCOUNT) { // Only valid at ACCOUNT state
            std::cout << "Sorry, command not valid at current state." << std::endl;
         } else if (tokens.size() == 2) {
            std::string id_str = tokens[1];
            try {
               // Try to convert table ID to int, send request over big endian
               uint16_t id = stoi(id_str);
               RemoveTablePDU *rt_pdu = new RemoveTablePDU(htons(id));
               ssize_t len = rt_pdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
               delete rt_pdu;
            }
            catch (const std::out_of_range& oor) {
               std::cout << "error, out of range" << std::endl;
            }
         } else {
            std::cout << "expected: remove <table id>" << std::endl;
         }
      } else if (command == "join") { // Join a table
         if (state != ACCOUNT) { // Only valid at ACCOUNT state
            std::cout << "Sorry, command not valid at current state." << std::endl;
         } else if (tokens.size() == 2) {
            std::string id_str = tokens[1];
            try {
               // Try to convert table ID to int, send request over big endian
               uint16_t id = stoi(id_str);
               JoinTablePDU *jt_pdu = new JoinTablePDU(htons(id));
               ssize_t len = jt_pdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
               delete jt_pdu;
            }
            catch (const std::out_of_range& oor) {
               std::cout << "error, out of range" << std::endl;
            }
         } else {
            std::cout << "expected: join <table id>" << std::endl;
         }
      } else if (command == "leave") { // Leave table
         if (state != ENTER_BETS && state != WAIT_FOR_TURN &&
               state != TURN && state != WAIT_FOR_DEALER &&
               state != IN_PROGRESS) {
            // current state MUST be a game state to leave a table
            std::cout << "Sorry, command not valid at current state." << std::endl;
         } else if (tokens.size() == 1) {
            // Send the leave request
            LeaveTablePDU *send_pdu = new LeaveTablePDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: leave" << std::endl;
         }
      } else if (command == "bet") { // Bet an amount on a current round.
         if (state != ENTER_BETS) { // Bet is only valid at the BET state
            std::cout << "Sorry, command not valid at current state." << std::endl;
         } if (tokens.size() == 2) {
            std::string amt_str = tokens[1];
            try {
               // Try to convert amount to an int, send over big endian
               uint32_t amt = stoi(amt_str);
               BetPDU *b_pdu = new BetPDU(htonl(amt));
               ssize_t len = b_pdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
               delete b_pdu;
            }
            catch (const std::out_of_range& oor) {
               std::cout << "error, out of range" << std::endl;
            }
         } else {
            std::cout << "expected: bet <amount>" << std::endl;
         }
      } else if (command == "hit") { // Hit (request a new card)
         if (state != TURN) { // Hit is only valid on your TURN
            std::cout << "Sorry, command not valid at current state." << std::endl;
         } else if (tokens.size() == 1) {
            // Send the hit request
            HitPDU *send_pdu = new HitPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: hit" << std::endl;
         }
      } else if (command == "stand") { // Stand (end turn)
         if (state != TURN) { // Stand is only valid on your TURN
            std::cout << "Sorry, command not valid at current state." << std::endl;
         } else if (tokens.size() == 1) {
            // Send the stand request
            StandPDU *send_pdu = new StandPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: stand" << std::endl;
         }
      } else if (command == "double") { // Double (increase bet, hit once)
         if (state != TURN) { // Double is only valid on your TURN
            std::cout << "Sorry, command not valid at current state." << std::endl;
         } else if (tokens.size() == 1) {
            // Send the double request
            DoubleDownPDU *send_pdu = new DoubleDownPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: double" << std::endl;
         }
      } else if (command == "chat") { // Send a chat message
         if (state != ENTER_BETS && state != WAIT_FOR_TURN &&
               state != TURN && state != WAIT_FOR_DEALER &&
               state != IN_PROGRESS) {
            // Chat only works at a game state
            std::cout << "Sorry, command not valid at current state." << std::endl;
         } else if (tokens.size() > 1) { // Need more than 1 token for chat
            // Build the chat message over the remaining tokens
            std::string msg = "";
            std::vector<std::string>::iterator it = tokens.begin();
            std::advance(it, 1); // Skip first token ("chat")
            msg += *it; // Get first token
            ++it;
            while (it != tokens.end()) {
               msg += " " + *it; // Add a space between each subsequent token
               ++it;
            }
            msg += "\n"; // Terminate in \n, send chat message
            ChatPDU *chat_pdu = new ChatPDU(msg);
            ssize_t len = chat_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete chat_pdu;
         } else {
            std::cout << "expected: chat <msg>" << std::endl;
         }
      } else {
         // Invalid command, print help
         std::cout << "Available commands:" << std::endl;
         std::cout << "> balance" << std::endl;
         std::cout << "> adjust <funds>" << std::endl;
         std::cout << "> quit" << std::endl;
         std::cout << "> list" << std::endl;
         std::cout << "> add" << std::endl;
         std::cout << "> remove <table id>" << std::endl;
         std::cout << "> join <table id>" << std::endl;
         std::cout << "> leave" << std::endl;
         std::cout << "> bet <amount>" << std::endl;
         std::cout << "> hit" << std::endl;
         std::cout << "> stand" << std::endl;
         std::cout << "> double" << std::endl;
         std::cout << "> chat <msg>" << std::endl;
      }
   }
   // Send a quit PDU on disconnect.
   QuitPDU *quit_pdu = new QuitPDU();
   len = quit_pdu->to_bytes(&write_buffer);
   SSL_write(ssl, write_buffer, len);
   delete quit_pdu;
   CONNECTED = false;
   // Disconnect, wait for listening thread to quit.
   listen.join();
   // Free the connection, close the socket, quit.
   SSL_free(ssl);
   close(sfd);
   SSL_CTX_free(ctx);
   return 0;
}

/* Stephen Hansen
 * 6/4/2021
 * CS 544
 *
 * server.cpp
 * This is it, the CBP server which runs the protocol and responds to client requests. The server also runs
 * a listening thread to UDP discovery on port 21211 for clients to discover the server (extra credit). The
 * server maintains a state for every client and implements the DFA in the main method to ensure commands are
 * only handled at each proper state. The server also uses threading to support multiple clients concurrently
 * and allows for client interaction in game threads.
 *
 * SSL TCP structure is sourced from https://github.com/rpoisel/ssl-echo/blob/master/echo_server_ssl.c.
 *
 * All other code is original and is fully mine.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <map>
#include <iostream>

#include <openssl/ssl.h>

#include "server.h"

/* prototypes */
static void sigIntHandler(int sig);
static void setup_libssl();
static void load_certs_keys(const char* cert_file, const char* key_file);
void connection_handler(int socket_conn);

/* globals */
int socket_listen = -1; // This is the socket int for the listening port
uint32_t server_version = 1; // Version number of server, sent and compared when receiving the VERSION negotiation PDU
SSL_CTX* ssl_ctx; // The SSL_CTX used by the server
/* main entry point */
int main(int argc, char* argv[])
{
   // SERVICE
   short port = 21210; // Default well-known port number
   short svc_disc = 21211;
   char* endptr = NULL;

   // Set up SSL_CTX
   setup_libssl();

   /* command line arguments */
   // SERVICE
   if (argc == 4) {
      // Read port, cert file, key file
      port = strtol(argv[1], &endptr, 0);
      if (*endptr) {
         fprintf(stderr, "Invalid port number.\n");
         exit(EXIT_FAILURE);
      }
      load_certs_keys(argv[2], argv[3]);
   } else if (argc == 3) {
      // Read cert file, key file
      // Port remains default 21210
      load_certs_keys(argv[1], argv[2]);
   } else {
      // Wrong arguments
      fprintf(stderr, "Usage: %s (<port-number>) <certificate-file> <key-file>\n",
            argv[0]);
      exit(EXIT_FAILURE);
   }

   /* signal handler to shutdown clearly */
   // Setup SIGINT to exit the program
   if (signal(SIGINT, sigIntHandler) == SIG_ERR)
   {
      perror("signal");
      exit(EXIT_FAILURE);
   }

   // Setup a socket connection listening to the given port number
   socket_listen = setup_socket(port);

   // Start up a UDP receiver thread to handle any broadcast messages sent by clients.
   // Give the thread the service discovery port, and the port at which CBP is actually running.
   std::thread udp_receiver(handle_broadcast, std::to_string(svc_disc), std::to_string(port));
   // Detach the receiver thread
   udp_receiver.detach();

   /* wait for connections */
   // Loop forever on accepting connections
   for (;;)
   {
      int socket_conn = -1;
      // Accept a new client connection
      if ((socket_conn = accept(socket_listen, NULL, NULL)) < 0)
      {
         perror("accept");
         exit(EXIT_FAILURE);
      }

      // CONCURRENT
      // Create a new thread that runs connection_handler for the given socket.
      std::thread conn(connection_handler, socket_conn);
      // Detach the connection thread
      conn.detach();
   }

   return EXIT_SUCCESS;
}

// sigIntHandler closes the listening socket, frees the SSL_CTX on shutdown (CTRL+C).
static void sigIntHandler(int sig)
{
   fprintf(stderr, "Shutting down ... \n");
   // Close socket
   if (socket_listen != -1)
   {
      close(socket_listen);
   }
   // Close SSL_CTX
   if (NULL != ssl_ctx)
   {
      SSL_CTX_free(ssl_ctx);
   }
   ssl_ctx = NULL;
   exit(EXIT_SUCCESS);
}

// setup_libssl sets up the initial SSL library and SSL_CTX
static void setup_libssl()
{
   SSL_library_init();
   SSL_load_error_strings();
   ssl_ctx = SSL_CTX_new(TLS_server_method());

   if (NULL == ssl_ctx)
   {
      fprintf(stderr, "Could not create SSL context(s).\n");
      exit(EXIT_FAILURE);
   }
}

// load_certs_keys loads the cert file and key file as given.
static void load_certs_keys(const char* cert_file, const char* key_file)
{
   if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file,
            SSL_FILETYPE_PEM) <= 0)
   {
      fprintf(stderr, "Could not load certificate file.\n");
      exit(EXIT_FAILURE);
   }
   if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file,
            SSL_FILETYPE_PEM) <= 0)
   {
      fprintf(stderr, "Could not load private key file.\n");
      exit(EXIT_FAILURE);
   }
   if (SSL_CTX_check_private_key(ssl_ctx) != 1)
   {
      fprintf(stderr, "Private key does not match "
            "the public certificate\n");
      exit(EXIT_FAILURE);
   }
}

// CONCURRENT
// connection_handler takes the socket connection and wraps it in SSL.
// The server then loops on parsing client PDUs and using the DFA
// implementation to send the appropriate response to the client at
// each step. This function runs in a unique thread per each
// connection.
void connection_handler(int socket_conn)
{
   SSL* ssl; /* SSL descriptor */
   int ret = -1;
   // Create new SSL connection
   if (NULL == (ssl = SSL_new(ssl_ctx)))
   {
      fprintf(stderr, "SSL_new failed.\n");
      exit(EXIT_FAILURE);
   }
   // Wrap the socket in SSL
   SSL_set_fd(ssl, socket_conn);

   // Initiate the TLS handshake
   ret = SSL_accept(ssl);
   if (ret != 1)
   {
      // Handshake failed
      fprintf(stderr, "SSL_accept failed: ");
      switch (SSL_get_error(ssl, ret))
      {
         case SSL_ERROR_ZERO_RETURN:
            fprintf(stderr, "SSL_ERROR_ZERO_RETURNn");
            break;
         case SSL_ERROR_WANT_READ:
            fprintf(stderr, "SSL_ERROR_WANT_READn");
            break;
         case SSL_ERROR_WANT_WRITE:
            fprintf(stderr, "SSL_ERROR_WANT_WRITEn");
            break;
         case SSL_ERROR_WANT_CONNECT:
            fprintf(stderr, "SSL_ERROR_WANT_CONNECTn");
            break;
         case SSL_ERROR_WANT_ACCEPT:
            fprintf(stderr, "SSL_ERROR_WANT_ACCEPTn");
            break;
         case SSL_ERROR_WANT_X509_LOOKUP:
            fprintf(stderr, "SSL_ERROR_WANT_X509_LOOKUPn");
            break;
         case SSL_ERROR_SYSCALL:
            fprintf(stderr, "SSL_ERROR_SYSCALLn");
            break;
         case SSL_ERROR_SSL:
            fprintf(stderr, "SSL_ERROR_SSLn");
            break;
         default:
            break;
      }
      fprintf(stderr, "\n");
      SSL_free(ssl);
      close(socket_conn);
      return;
   }

   // At this point the SSL connection is established
   // Set the connection to the VERSION state.
   conn_to_state[ssl] = VERSION;
   std::string username = "";
   std::string password = "";

   char * write_buffer = (char *)malloc(4096);
   /* handle connections */
   for (;;)
   {
      // Get the next PDU from client
      PDU * p = parse_pdu_server(ssl);
      // Client sent no PDU... client connection is gone.
      if (!p)
      {
         fprintf(stderr, "Closing client connection. \n");
         break;
      }
      // Check if user sends quit, valid at any state (no need to state check here)
      QuitPDU* quit_pdu = dynamic_cast<QuitPDU*>(p);
      if (quit_pdu) {
         // Leave table if at a table
         leavetable(ssl);
         // Break the loop on reading PDUs
         break;
      }
      // STATEFUL
      // Here we check the state for the current connection and use that to guide
      // responses. Any command not handled at the current state is sent an error response.
      if (conn_to_state[ssl] == VERSION) {
         // VersionPDU is the only valid PDU at version
         VersionPDU* version_pdu = dynamic_cast<VersionPDU*>(p);
         if (!version_pdu) { // PDU is not version
            // Send error, close connection
            VersionResponsePDU *pdu = new VersionResponsePDU(5, 0, 1, htonl(server_version));
            ssize_t len = pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            break;
         }
         uint32_t client_version = version_pdu->getVersion();
         if (client_version == server_version) { // Client has the same version as server
            // Supported, send 2-0-1 and move to USERNAME
            VersionResponsePDU *pdu = new VersionResponsePDU(2, 0, 1, htonl(server_version));
            ssize_t len = pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            conn_to_state[ssl] = USERNAME;
         } else {
            // Not supported. Send error, close connection
            VersionResponsePDU *pdu = new VersionResponsePDU(5, 0, 1, htonl(server_version));
            ssize_t len = pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            // Immediately disconnect due to wrong version
            break;
         }
      } else if (conn_to_state[ssl] == USERNAME) {
         // UserPDU is the only valid PDU here
         UserPDU* user_pdu = dynamic_cast<UserPDU*>(p);
         if (!user_pdu) { // Not a UserPDU
            // Send error, continue connection
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 0, 0, "Wrong command, expected USER.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            continue;
         }
         // Accept whatever the username is, move to PASSWORD
         username = user_pdu->getUsername();
         conn_to_state[ssl] = PASSWORD;
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(3, 0, 0, "Provide password.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (conn_to_state[ssl] == PASSWORD) {
         // PassPDU is the only valid PDU here
         PassPDU* pass_pdu = dynamic_cast<PassPDU*>(p);
         if (!pass_pdu) { // Not a PassPDU
            // Send error, continue connection but go back to USERNAME
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 0, 0, "Wrong command, expected PASS. Going back to USERNAME state.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            conn_to_state[ssl] = USERNAME;
            continue;
         }
         // Accept whatever the password is, check auth
         password = pass_pdu->getPassword();
         if ((auth_credentials.find(username) == auth_credentials.end()) || (auth_credentials[username] != password)) {
            // No username or wrong password
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 0, 2, "Authentication failed.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            conn_to_state[ssl] = USERNAME;
         } else {
            // Valid login; proceed to ACCOUNT, send 2-0-2
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(2, 0, 2, "Authenticated successfully.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            // Map connection to given username
            conn_to_user[ssl] = username;
            // Create new account details on first join
            if (user_info.find(username) == user_info.end()) {
               user_info[username] = new AccountDetails();
            }
            conn_to_state[ssl] = ACCOUNT;
         }
      } else if (conn_to_state[ssl] == ACCOUNT) {
         // Attempt to handle get balance PDU
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         // Attempt to handle update to balance PDU
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
         GetTablesPDU* gt_pdu = dynamic_cast<GetTablesPDU*>(p);
         if (gt_pdu) { // PDU is GetTables
            std::vector<TabledataPDU*> tabledata;
            // Go through all tables, get a list of tabledata
            for (std::map<uint16_t, TableDetails*>::iterator it = tables.begin(); it != tables.end(); it++) {
               uint16_t tid = it->first;
               std::string settings = it->second->to_string(); // Convert each table to a string
               TabledataPDU* td = new TabledataPDU(htons(tid), settings); // Create a tabledata for the table ID and settings
               tabledata.push_back(td);
            }
            // No tables available, send error
            if (tabledata.size() == 0) {
               ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 1, "No tables available.\n\n");
               ssize_t len = rpdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
            } else {
               // Tables available, send list of tabledata in 2-1-1 ListTables response
               ListTablesResponsePDU* ltr_pdu = new ListTablesResponsePDU(2, 1, 1, tabledata);
               ssize_t len = ltr_pdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
            }
            continue;
         }
         // Attempt to handle add table
         if (handle_addtable(p, ssl)) {
            continue;
         }
         RemoveTablePDU* rt_pdu = dynamic_cast<RemoveTablePDU*>(p);
         if (rt_pdu) { // User sent RemoveTable
            uint16_t table_id = rt_pdu->getTableID(); // get table to remove
            if (tables.find(table_id) != tables.end()) { // table ID exists
               tables_lock.lock(); // lock the list of tables
               tables[table_id]->shutdown(); // shutdown game (kick all players out)
               tables.erase(table_id); // remove table
               tables_lock.unlock();
               // Inform of success
               ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(2, 1, 0, "Successfully shut down table.\n\n");
               ssize_t len = rpdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
            } else {
               // Inform failure
               ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 2, "Table with ID does not exist.\n\n");
               ssize_t len = rpdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
            }
            continue;
         }
         JoinTablePDU* jt_pdu = dynamic_cast<JoinTablePDU*>(p);
         if (jt_pdu) { // User sent JoinTable
            uint16_t table_id = jt_pdu->getTableID(); // get table to join
            if (tables.find(table_id) != tables.end()) { // table ID exists
               conn_to_table_id[ssl] = table_id; // map connection to table ID
               tables[table_id]->add_player(ssl); // add player to table (this will handle state transition, response)
            } else {
               // Table does not exist, inform failure
               ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 2, "Table with ID does not exist.\n\n");
               ssize_t len = rpdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
            }
            continue;
         }
         // Must be an invalid PDU at this state, send error
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 0, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (conn_to_state[ssl] == IN_PROGRESS) {
         // This state only handles balance commands, leavetable, and chat, nothing else
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
         if (handle_leavetable(p, ssl)) {
            continue;
         }
         if (handle_chat(p, ssl)) {
            continue;
         }
         // At this point, PDU must not be valid for state, send error
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (conn_to_state[ssl] == ENTER_BETS) {
         // Attempt to handle either getbalance, updatebalance, leavetable, or chat first
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
         if (handle_leavetable(p, ssl)) {
            continue;
         }
         if (handle_chat(p, ssl)) {
            continue;
         }
         BetPDU* b_pdu = dynamic_cast<BetPDU*>(p);
         if (b_pdu) { // PDU is bet
            uint32_t amt = b_pdu->getBetAmount(); // Get amount to bet
            if (amt > user_info[conn_to_user[ssl]]->getBalance()) { // Check if amount does not fit in balance for username
               // Amount out of range
               ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "You do not have sufficient funds to make this bet.\n\n");
               ssize_t len = rpdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
               continue;
            }
            uint16_t table_id = conn_to_table_id[ssl]; // Get player's current table
            if (!tables[table_id]->betInRange(amt)) { // Check if bet in accepted table range
               // Bet out of table range, send error
               ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Bet not in range allowed by table.\n\n");
               ssize_t len = rpdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
               continue;
            }
            // Get the player's info at the current table
            PlayerInfo* pi = tables[table_id]->getPlayerInfo(ssl);
            // Set the player's bet
            pi->setBet(amt);
            // Remove the bet amount from the username's account info
            user_info[conn_to_user[ssl]]->adjustBalance(-amt);
            // Inform player of bet success
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(2, 1, 0, "Accepted bet, please wait for turn.\n\n");
            // Move to WAIT_FOR_TURN
            conn_to_state[ssl] = WAIT_FOR_TURN;
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            continue;
         }
         // At this point command must be invalid for state, send error
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (conn_to_state[ssl] == WAIT_FOR_TURN) {
         // This state only handles balance commands, leavetable, and chat, nothing else
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
         if (handle_leavetable(p, ssl)) {
            continue;
         }
         if (handle_chat(p, ssl)) {
            continue;
         }
         // Command must not be valid, send error
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (conn_to_state[ssl] == TURN) {
         // TURN can handle getbalance, updatebalance, leavetable, hit, stand, doubledown, and chat.
         // State transitions, responses are in those respective methods.
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
         if (handle_leavetable(p, ssl)) {
            continue;
         }
         if (handle_hit(p, ssl)) {
            continue;
         }
         if (handle_stand(p, ssl)) {
            continue;
         }
         if (handle_doubledown(p, ssl)) {
            continue;
         }
         if (handle_chat(p, ssl)) {
            continue;
         }
         // Command must not be valid, send error
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (conn_to_state[ssl] == WAIT_FOR_DEALER) {
         // This state only handles balance commands, leavetable, and chat, nothing else
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
         if (handle_leavetable(p, ssl)) {
            continue;
         }
         if (handle_chat(p, ssl)) {
            continue;
         }
         // Command must not be valid, send error
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      }
   }
   // PDU failed to parse here, or quit, remove the client connection.
   free(write_buffer);
   /* close connection to client */
   leavetable(ssl); // Remove player from current table (if they are at any)
   SSL_free(ssl); // Free the SSL connection
   if (close(socket_conn) < 0) // Close the socket.
   {
      fprintf(stderr, "Error during close(2). \n");
      exit(EXIT_FAILURE);
   }
   socket_conn = -1;
}


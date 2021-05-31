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
int socket_listen = -1;
uint32_t server_version = 1;
SSL_CTX* ssl_ctx;
/* main entry point */
int main(int argc, char* argv[])
{
   short port = -1;
   char* endptr = NULL;

   setup_libssl();

   /* command line arguments */
   if (argc == 4)
   {
      port = strtol(argv[1], &endptr, 0);
      if (*endptr)
      {
         fprintf(stderr, "Invalid port number.\n");
         exit(EXIT_FAILURE);
      }
      load_certs_keys(argv[2], argv[3]);
   }
   else
   {
      fprintf(stderr, "Usage: %s <port-number> <certificate-file> <key-file>\n",
            argv[0]);
      exit(EXIT_FAILURE);
   }

   /* signal handler to shutdown clearly */
   if (signal(SIGINT, sigIntHandler) == SIG_ERR)
   {
      perror("signal");
      exit(EXIT_FAILURE);
   }

   socket_listen = setup_socket(port);

   /* wait for connections */
   for (;;)
   {
      int socket_conn = -1;
      if ((socket_conn = accept(socket_listen, NULL, NULL)) < 0)
      {
         perror("accept");
         exit(EXIT_FAILURE);
      }

      std::thread conn(connection_handler, socket_conn);
      conn.detach();
   }

   return EXIT_SUCCESS;
}

static void sigIntHandler(int sig)
{
   fprintf(stderr, "Shutting down ... \n");
   if (socket_listen != -1)
   {
      close(socket_listen);
   }
   //if (socket_conn != -1)
   //{
   //   close(socket_conn);
   //}
   if (NULL != ssl_ctx)
   {
      SSL_CTX_free(ssl_ctx);
   }
   ssl_ctx = NULL;
   exit(EXIT_SUCCESS);
}

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

void connection_handler(int socket_conn)
{
   SSL* ssl; /* SSL descriptor */
   int ret = -1;
   if (NULL == (ssl = SSL_new(ssl_ctx)))
   {
      fprintf(stderr, "SSL_new failed.\n");
      exit(EXIT_FAILURE);
   }
   SSL_set_fd(ssl, socket_conn);

   ret = SSL_accept(ssl);
   if (ret != 1)
   {
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
      PDU * p = parse_pdu_server(ssl); 
      if (!p)
      {
         fprintf(stderr, "Closing client connection. \n");
         break;
      }
      // Check if user sends quit, valid at any state
      QuitPDU* quit_pdu = dynamic_cast<QuitPDU*>(p);
      if (quit_pdu) {
         // Leave table if at a table
         leavetable(ssl);
         // Close the connection
         break;
      }
      if (conn_to_state[ssl] == VERSION) {
         VersionPDU* version_pdu = dynamic_cast<VersionPDU*>(p);
         if (!version_pdu) {
            // Send error, close connection
            VersionResponsePDU *pdu = new VersionResponsePDU(5, 0, 1, htonl(server_version));
            ssize_t len = pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            break;
         }
         uint32_t client_version = version_pdu->getVersion();
         if (client_version == server_version) {
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
            break;
         }
      } else if (conn_to_state[ssl] == USERNAME) {
         UserPDU* user_pdu = dynamic_cast<UserPDU*>(p);
         if (!user_pdu) {
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
         PassPDU* pass_pdu = dynamic_cast<PassPDU*>(p);
         if (!pass_pdu) {
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
            conn_to_user[ssl] = username;
            if (user_info.find(username) == user_info.end()) {
               user_info[username] = new AccountDetails();
            }
            conn_to_state[ssl] = ACCOUNT;
         }
      } else if (conn_to_state[ssl] == ACCOUNT) {
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
         GetTablesPDU* gt_pdu = dynamic_cast<GetTablesPDU*>(p);
         if (gt_pdu) {
            std::vector<TabledataPDU*> tabledata;
            for (std::map<uint16_t, TableDetails*>::iterator it = tables.begin(); it != tables.end(); it++) {
               uint16_t tid = it->first;
               std::string settings = it->second->to_string();
               TabledataPDU* td = new TabledataPDU(htonl(tid), settings);
               tabledata.push_back(td);
            }
            if (tabledata.size() == 0) {
               ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 1, "No tables available.\n\n");
               ssize_t len = rpdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
            } else {
               ListTablesResponsePDU* ltr_pdu = new ListTablesResponsePDU(2, 1, 1, tabledata);
               ssize_t len = ltr_pdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
            }
            continue;
         }
         AddTablePDU* at_pdu = dynamic_cast<AddTablePDU*>(p);
         if (at_pdu) {
            // TODO
            continue;
         }
         RemoveTablePDU* rt_pdu = dynamic_cast<RemoveTablePDU*>(p);
         if (rt_pdu) {
            // TODO
            continue;
         }
         JoinTablePDU* jt_pdu = dynamic_cast<JoinTablePDU*>(p);
         if (jt_pdu) {
            uint16_t table_id = jt_pdu->getTableID();
            if (tables.find(table_id) != tables.end()) {
               conn_to_table_id[ssl] = table_id;
               tables[table_id]->add_player(ssl);
            } else {
               ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(4, 1, 2, "Table with ID does not exist.\n\n");
               ssize_t len = rpdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
            }
            continue;
         }
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 0, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (conn_to_state[ssl] == IN_PROGRESS) {
         // This state only handles balance commands and leavetable, nothing else
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
         if (handle_leavetable(p, ssl)) {
            continue;
         }
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (conn_to_state[ssl] == ENTER_BETS) {
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
         if (handle_leavetable(p, ssl)) {
            continue;
         }
         BetPDU* b_pdu = dynamic_cast<BetPDU*>(p);
         if (b_pdu) {
            conn_to_state[ssl] = WAIT_FOR_TURN;
            uint32_t amt = b_pdu->getBetAmount();
            if (amt > user_info[conn_to_user[ssl]]->getBalance()) {
               ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "You do not have sufficient funds to make this bet.\n\n");
               ssize_t len = rpdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
               continue;
            }
            uint16_t table_id = conn_to_table_id[ssl];
            if (!tables[table_id]->betInRange(amt)) {
               ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Bet not in range allowed by table.\n\n");
               ssize_t len = rpdu->to_bytes(&write_buffer);
               SSL_write(ssl, write_buffer, len);
               continue;
            }
            PlayerInfo* pi = tables[table_id]->getPlayerInfo(ssl);
            pi->setBet(amt);
            user_info[conn_to_user[ssl]]->adjustBalance(-amt);
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(2, 1, 0, "Accepted bet, please wait for turn.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            continue;
         }
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (conn_to_state[ssl] == WAIT_FOR_TURN) {
         // This state only handles balance commands and leavetable, nothing else
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
         if (handle_leavetable(p, ssl)) {
            continue;
         }
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (conn_to_state[ssl] == TURN) {
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
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (conn_to_state[ssl] == WAIT_FOR_DEALER) {
         // This state only handles balance commands and leavetable, nothing else
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
         if (handle_leavetable(p, ssl)) {
            continue;
         }
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 1, 0, "Command not accepted at current state.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      }
   }
   free(write_buffer);
   /* close connection to client */
   SSL_free(ssl);
   if (close(socket_conn) < 0)
   {
      fprintf(stderr, "Error during close(2). \n");
      exit(EXIT_FAILURE);
   }
   socket_conn = -1;
}


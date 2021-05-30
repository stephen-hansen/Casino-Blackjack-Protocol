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
#include "../protocol/dfa.h"

#define MAX_STR_LEN 1028

/* additional info
 * http://simplestcodings.blogspot.com.br/2010/08/secure-server-client-using-openssl-in-c.html
 * http://stackoverflow.com/questions/11705815/client-and-server-communication-using-ssl-c-c-ssl-protocol-dont-works
 * http://lcalligaris.wordpress.com/2011/04/07/implementing-a-secure-socket/
 */

/* prototypes */
static void sigIntHandler(int sig);
static void setup_libssl();
static void load_certs_keys(const char* cert_file, const char* key_file);
static void connection_handler();

/* globals */
int socket_listen = -1;
int socket_conn = -1;
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
      if ((socket_conn = accept(socket_listen, NULL, NULL)) < 0)
      {
         perror("accept");
         exit(EXIT_FAILURE);
      }

      connection_handler();
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
   if (socket_conn != -1)
   {
      close(socket_conn);
   }
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
   ssl_ctx = SSL_CTX_new(SSLv23_server_method());

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

static void connection_handler()
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
   STATE curr_state = VERSION;
   std::string username = "";
   std::string password = "";

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
         // Close the connection
         break;
      }
      if (curr_state == VERSION) {
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
            curr_state = USERNAME;
         } else {
            // Not supported. Send error, close connection
            VersionResponsePDU *pdu = new VersionResponsePDU(5, 0, 1, htonl(server_version));
            ssize_t len = pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            break;
         }
      } else if (curr_state == USERNAME) {
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
         curr_state = PASSWORD;
         ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(3, 0, 0, "Provide password.\n\n");
         ssize_t len = rpdu->to_bytes(&write_buffer);
         SSL_write(ssl, write_buffer, len);
      } else if (curr_state == PASSWORD) {
         PassPDU* pass_pdu = dynamic_cast<PassPDU*>(p);
         if (!pass_pdu) {
            // Send error, continue connection but go back to USERNAME
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 0, 0, "Wrong command, expected PASS. Going back to USERNAME state.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            curr_state = USERNAME;
            continue;
         }
         // Accept whatever the password is, check auth
         password = pass_pdu->getPassword();
         if ((auth_credentials.find(username) == auth_credentials.end()) || (auth_credentials[username] != password)) {
            // No username or wrong password
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(5, 0, 2, "Authentication failed.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            curr_state = USERNAME;
         } else {
            // Valid login; proceed to ACCOUNT, send 2-0-2
            ASCIIResponsePDU* rpdu = new ASCIIResponsePDU(2, 0, 2, "Authenticated successfully.\n\n");
            ssize_t len = rpdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            // Initialize balance TODO check key
            conn_to_user[ssl] = username;
            user_info[username] = new AccountDetails();
            curr_state = ACCOUNT;
         }
      } else if (curr_state == ACCOUNT) {
         if (handle_getbalance(p, ssl)) {
            continue;
         }
         if (handle_updatebalance(p, ssl)) {
            continue;
         }
      }
   }

   /* close connection to client */
   SSL_free(ssl);
   if (close(socket_conn) < 0)
   {
      fprintf(stderr, "Error during close(2). \n");
      exit(EXIT_FAILURE);
   }
   socket_conn = -1;
}


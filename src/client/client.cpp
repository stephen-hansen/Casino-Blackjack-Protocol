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

int OpenConnection(const char *hostname, const char *port)
{
   struct hostent *host;
   if ((host = gethostbyname(hostname)) == nullptr)
   {
      perror(hostname);
      exit(EXIT_FAILURE);
   }

   struct addrinfo hints = {0}, *addrs;
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_protocol = IPPROTO_TCP;

   const int status = getaddrinfo(hostname, port, &hints, &addrs);
   if (status != 0)
   {
      fprintf(stderr, "%s: %s\n", hostname, gai_strerror(status));
      exit(EXIT_FAILURE);
   }

   int sfd, err;
   for (struct addrinfo *addr = addrs; addr != nullptr; addr = addr->ai_next)
   {
      sfd = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
      if (sfd == ERROR_STATUS)
      {
         err = errno;
         continue;
      }

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
   return sfd;
}

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

int main(int argc, char const *argv[])
{
   char * write_buffer = (char*)malloc(4096);
   SSL_CTX *ctx = InitSSL_CTX();
   SSL *ssl = SSL_new(ctx);
   if (ssl == nullptr)
   {
      fprintf(stderr, "SSL_new() failed\n");
      exit(EXIT_FAILURE);
   }

   //Host is hardcoded to localhost for testing purposes
   const int sfd = OpenConnection("127.0.0.1", argv[1]);
   SSL_set_fd(ssl, sfd);

   const int status = SSL_connect(ssl);
   if (status != 1)
   {
      SSL_get_error(ssl, status);
      ERR_print_errors_fp(stderr); //High probability this doesn't do anything
      fprintf(stderr, "SSL_connect failed with SSL_get_error code %d\n", status);
      exit(EXIT_FAILURE);
   }

   printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
   DisplayCerts(ssl);
   // Start up a listening thread
   std::thread listen(listen_to_server,ssl);
   // Send VERSION on connection
   uint32_t version = htonl(1); // Version 1, over big endian
   VersionPDU *version_pdu = new VersionPDU(version);
   ssize_t len = version_pdu->to_bytes(&write_buffer);
   SSL_write(ssl, write_buffer, len);
   delete version_pdu;
   for (std::string line; std::getline(std::cin, line);) {
      std::istringstream iss(line);
      std::vector<std::string> tokens;
      std::copy(std::istream_iterator<std::string>(iss), std::istream_iterator<std::string>(), std::back_inserter(tokens));
      if (tokens.size() < 1) {
         std::cout << "expected: <command> (<arg1> <arg2> <arg3> ...)" << std::endl;
         continue;
      }
      std::string command = tokens[0];
      if (command == "user") {
         if (tokens.size() == 2) {
            std::string username = tokens[1];
            username.append("\n");
            UserPDU *user_pdu = new UserPDU(username);
            ssize_t len = user_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete user_pdu;
         } else {
            std::cout << "expected: user <username>" << std::endl;
         }
      } else if (command == "pass") {
         if (tokens.size() == 2) {
            std::string password = tokens[1];
            password.append("\n");
            PassPDU *pass_pdu = new PassPDU(password);
            ssize_t len = pass_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete pass_pdu;
         } else {
            std::cout << "expected: pass <password>" << std::endl;
         }
      } else if (command == "getbalance") {
         if (tokens.size() == 1) {
            GetBalancePDU *gb_pdu = new GetBalancePDU();
            ssize_t len = gb_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete gb_pdu;
         } else {
            std::cout << "expected: getbalance" << std::endl;
         }
      } else if (command == "updatebalance") {
      } else if (command == "quit") {
         if (tokens.size() == 1) {
            QuitPDU *quit_pdu = new QuitPDU();
            ssize_t len = quit_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete quit_pdu;
            break;
         } else {
            std::cout << "expected: quit" << std::endl;
         }
      } else if (command == "gettables") {
      } else if (command == "addtable") {
      } else if (command == "removetable") {
      } else if (command == "jointable") {
      } else if (command == "leavetable") {
      } else if (command == "bet") {
      } else if (command == "insurance") {
      } else if (command == "hit") {
      } else if (command == "stand") {
      } else if (command == "doubledown") {
      } else if (command == "split") {
      } else if (command == "surrender") {
      } else if (command == "chat") {
      } else {
         std::cout << "Invalid command" << std::endl;
      }
   }
   SSL_free(ssl);
   close(sfd);
   SSL_CTX_free(ctx);
   return 0;
}

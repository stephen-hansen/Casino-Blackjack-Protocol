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

   const char * port_number = "21210";
   if (argc == 3) {
      port_number = argv[2];
   } else if (argc != 2) {
      fprintf(stderr, "Expected arguments <hostname/ip> (<port>)");
      exit(EXIT_FAILURE);
   }

   const int sfd = OpenConnection(argv[1], port_number);
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
         if (tokens.size() == 2) {
            std::string funds_str = tokens[1];
            int32_t funds = stoi(funds_str);
            UpdateBalancePDU *ub_pdu = new UpdateBalancePDU(htonl(funds));
            ssize_t len = ub_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete ub_pdu;
         } else {
            std::cout << "expected: updatebalance <funds>" << std::endl;
         }
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
         if (tokens.size() == 1) {
            GetTablesPDU *send_pdu = new GetTablesPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: gettables" << std::endl;
         }
      } else if (command == "addtable") {
         // TODO interactive
      } else if (command == "removetable") {
         if (tokens.size() == 2) {
            std::string id_str = tokens[1];
            uint16_t id = stoi(id_str);
            RemoveTablePDU *rt_pdu = new RemoveTablePDU(htons(id));
            ssize_t len = rt_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete rt_pdu;
         } else {
            std::cout << "expected: removetable <table id>" << std::endl;
         }
      } else if (command == "jointable") {
         if (tokens.size() == 2) {
            std::string id_str = tokens[1];
            uint16_t id = stoi(id_str);
            JoinTablePDU *jt_pdu = new JoinTablePDU(htons(id));
            ssize_t len = jt_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete jt_pdu;
         } else {
            std::cout << "expected: jointable <table id>" << std::endl;
         }
      } else if (command == "leavetable") {
         if (tokens.size() == 1) {
            LeaveTablePDU *send_pdu = new LeaveTablePDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: leavetable" << std::endl;
         }
      } else if (command == "bet") {
         if (tokens.size() == 2) {
            std::string amt_str = tokens[1];
            uint32_t amt = stoi(amt_str);
            BetPDU *b_pdu = new BetPDU(htonl(amt));
            ssize_t len = b_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete b_pdu;
         } else {
            std::cout << "expected: bet <amount>" << std::endl;
         }
      } else if (command == "insurance") {
         if (tokens.size() == 2) {
            std::string accepted_str = tokens[1];
            uint8_t accepted;
            if (accepted_str == "yes") {
               accepted = 1;
            } else if (accepted_str == "no") {
               accepted = 0;
            } else {
               std::cout << "expected: insurance (yes/no)" << std::endl;
               continue;
            }
            InsurancePDU *i_pdu = new InsurancePDU(accepted);
            ssize_t len = i_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete i_pdu;
         } else {
            std::cout << "expected: insurance (yes/no)" << std::endl;
         }
      } else if (command == "hit") {
         if (tokens.size() == 1) {
            HitPDU *send_pdu = new HitPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: hit" << std::endl;
         }
      } else if (command == "stand") {
         if (tokens.size() == 1) {
            StandPDU *send_pdu = new StandPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: stand" << std::endl;
         }
      } else if (command == "doubledown") {
         if (tokens.size() == 1) {
            DoubleDownPDU *send_pdu = new DoubleDownPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: doubledown" << std::endl;
         }
      } else if (command == "split") {
         if (tokens.size() == 1) {
            SplitPDU *send_pdu = new SplitPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: split" << std::endl;
         }
      } else if (command == "surrender") {
         if (tokens.size() == 1) {
            SurrenderPDU *send_pdu = new SurrenderPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: surrender" << std::endl;
         }
      } else if (command == "chat") {
         if (tokens.size() > 1) {
            std::string msg = "";
            std::vector<std::string>::iterator it = tokens.begin();
            std::advance(it, 1);
            msg += *it;
            ++it;
            while (it != tokens.end()) {
               msg += " " + *it;
               ++it;
            }
            msg += "\n";
            ChatPDU *chat_pdu = new ChatPDU(msg);
            ssize_t len = chat_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete chat_pdu;
         } else {
            std::cout << "expected: chat <msg>" << std::endl;
         }
      } else if (command == "help") {
         std::cout << "Available commands:" << std::endl;
         std::cout << "user <username>" << std::endl;
         std::cout << "pass <password>" << std::endl;
         std::cout << "getbalance" << std::endl;
         std::cout << "updatebalance <funds>" << std::endl;
         std::cout << "quit" << std::endl;
         std::cout << "gettables" << std::endl;
         std::cout << "addtable" << std::endl;
         std::cout << "removetable <table id>" << std::endl;
         std::cout << "jointable <table id>" << std::endl;
         std::cout << "leavetable" << std::endl;
         std::cout << "bet <amount>" << std::endl;
         std::cout << "insurance (yes/no)" << std::endl;
         std::cout << "hit" << std::endl;
         std::cout << "stand" << std::endl;
         std::cout << "doubledown" << std::endl;
         std::cout << "split" << std::endl;
         std::cout << "surrender" << std::endl;
         std::cout << "chat <msg>" << std::endl;
      } else {
         std::cout << "Invalid command" << std::endl;
      }
   }
   SSL_free(ssl);
   close(sfd);
   SSL_CTX_free(ctx);
   return 0;
}

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

   const char * ip;
   const char * port_number = "21210";
   if (argc == 3) {
      ip = argv[1];
      port_number = argv[2];
   } else if (argc == 2) {
      ip = argv[1];
   } else if (argc == 1) {
      // Service discovery
      std::cout << "Searching for nearest CBP server..." << std::endl;
      std::string ip_port = get_blackjack_server("0.0.0.0", "21211");
      size_t colon_loc = ip_port.find('/');
      ip = ip_port.substr(0, colon_loc).c_str();
      port_number = ip_port.substr(colon_loc+1).c_str();
   } else {
      fprintf(stderr, "Expected arguments (<hostname/ip>) (<port>)");
      exit(EXIT_FAILURE);
   }

   const int sfd = OpenConnection(ip, port_number);
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
   // Send VERSION on connection
   uint32_t version = htonl(1); // Version 1, over big endian
   VersionPDU *version_pdu = new VersionPDU(version);
   ssize_t len = version_pdu->to_bytes(&write_buffer);
   SSL_write(ssl, write_buffer, len);
   delete version_pdu;
   VersionResponsePDU *vr_pdu = dynamic_cast<VersionResponsePDU*>(parse_pdu_client(ssl));
   if (!vr_pdu || vr_pdu->getReplyCode1() != 2) {
      fprintf(stderr, "Client is not running supported version.\n");
      exit(EXIT_FAILURE);
   }
   bool authenticated = false;
   std::string line;
   while (!authenticated) {
      std::cout << "Enter username: ";
      std::getline(std::cin, line);
      line.append("\n");
      UserPDU *user_pdu = new UserPDU(line);
      ssize_t len = user_pdu->to_bytes(&write_buffer);
      SSL_write(ssl, write_buffer, len);
      delete user_pdu;
      ASCIIResponsePDU *user_resp = dynamic_cast<ASCIIResponsePDU*>(parse_pdu_client(ssl));
      if (!user_resp || user_resp->getReplyCode1() == 4 || user_resp->getReplyCode1() == 5) {
         fprintf(stderr, "Got an unexpected error from server.\n");
         exit(EXIT_FAILURE);
      }
      std::cout << "Enter password: ";
      std::getline(std::cin, line);
      line.append("\n");
      PassPDU *pass_pdu = new PassPDU(line);
      len = pass_pdu->to_bytes(&write_buffer);
      SSL_write(ssl, write_buffer, len);
      delete pass_pdu;
      ASCIIResponsePDU *pass_resp = dynamic_cast<ASCIIResponsePDU*>(parse_pdu_client(ssl));
      if (!pass_resp || pass_resp->getReplyCode1() != 2) {
         std::cout << "Invalid username/password" << std::endl;
      } else {
         std::cout << "Successfully authenticated" << std::endl;
         authenticated = true;
      }
   }
   // Start up a listening thread
   std::thread listen(listen_to_server,ssl);
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
   for (; std::getline(std::cin, line);) {
      std::istringstream iss(line);
      std::vector<std::string> tokens;
      std::copy(std::istream_iterator<std::string>(iss), std::istream_iterator<std::string>(), std::back_inserter(tokens));
      if (tokens.size() < 1) {
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
      std::string command = tokens[0];
      if (command == "balance") {
         if (tokens.size() == 1) {
            GetBalancePDU *gb_pdu = new GetBalancePDU();
            ssize_t len = gb_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete gb_pdu;
         } else {
            std::cout << "expected: balance" << std::endl;
         }
      } else if (command == "adjust") {
         if (tokens.size() == 2) {
            std::string funds_str = tokens[1];
            int32_t funds = stoi(funds_str);
            UpdateBalancePDU *ub_pdu = new UpdateBalancePDU(htonl(funds));
            ssize_t len = ub_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete ub_pdu;
         } else {
            std::cout << "expected: adjust <funds>" << std::endl;
         }
      } else if (command == "quit") {
         if (tokens.size() == 1) {
            break;
         } else {
            std::cout << "expected: quit" << std::endl;
         }
      } else if (command == "list") {
         if (tokens.size() == 1) {
            GetTablesPDU *send_pdu = new GetTablesPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: list" << std::endl;
         }
      } else if (command == "add") {
         // TODO interactive
      } else if (command == "remove") {
         if (tokens.size() == 2) {
            std::string id_str = tokens[1];
            uint16_t id = stoi(id_str);
            RemoveTablePDU *rt_pdu = new RemoveTablePDU(htons(id));
            ssize_t len = rt_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete rt_pdu;
         } else {
            std::cout << "expected: remove <table id>" << std::endl;
         }
      } else if (command == "join") {
         if (tokens.size() == 2) {
            std::string id_str = tokens[1];
            uint16_t id = stoi(id_str);
            JoinTablePDU *jt_pdu = new JoinTablePDU(htons(id));
            ssize_t len = jt_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete jt_pdu;
         } else {
            std::cout << "expected: join <table id>" << std::endl;
         }
      } else if (command == "leave") {
         if (tokens.size() == 1) {
            LeaveTablePDU *send_pdu = new LeaveTablePDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: leave" << std::endl;
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
      } else if (command == "double") {
         if (tokens.size() == 1) {
            DoubleDownPDU *send_pdu = new DoubleDownPDU();
            ssize_t len = send_pdu->to_bytes(&write_buffer);
            SSL_write(ssl, write_buffer, len);
            delete send_pdu;
         } else {
            std::cout << "expected: double" << std::endl;
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
      } else {
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
   QuitPDU *quit_pdu = new QuitPDU();
   len = quit_pdu->to_bytes(&write_buffer);
   SSL_write(ssl, write_buffer, len);
   delete quit_pdu;
   SSL_free(ssl);
   close(sfd);
   SSL_CTX_free(ctx);
   return 0;
}

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "../protocol/pdu.h"

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
         Version v;
         v.category_code = 0;
         v.command_code = 0;
         v.version = *reinterpret_cast<uint32_t*>(message_buf);
         pdu = new VersionPDU(v);
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
            message_buf[i+1] = '\0';
            // Convert to string, create pdu
            pdu = new UserPDU(*header, std::string(message_buf));
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
            message_buf[i+1] = '\0';
            // Convert to string, create pdu
            pdu = new PassPDU(*header, std::string(message_buf));
         }
      } else if (command_code == 3) { // GETBALANCE
         // No additional parsing necessary
         pdu = new GetBalancePDU(*header);
      } else if (command_code == 4) { // UPDATEBALANCE
         char message_buf[4];
         // Read in the funds
         if ((rc = SSL_read(ssl, message_buf, 4)) <= 0) {
            return pdu;
         }
         UpdateBalance u;
         u.category_code = 0;
         u.command_code = 4;
         u.funds = *reinterpret_cast<uint32_t*>(message_buf);
         pdu = new UpdateBalancePDU(u);
      } else if (command_code == 5) { // QUIT
         // No additional parsing necessary
         pdu = new QuitPDU(*header);
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


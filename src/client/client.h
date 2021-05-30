#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <iostream>
#include <map>
#include <mutex>
#include <vector>

#include "../protocol/pdu.h"

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
   } else if (rc1 == 2 && rc2 == 1 && rc3 == 4) {
      // Handle addtable response
   } else if (rc1 == 3 && rc2 == 1 && rc3 == 0) {
      // Handle jointable response
   } else if ((rc1 == 1 && rc2 == 1 && (rc3 >= 1 && rc3 <= 6 && rc3 != 5)) ||
         (rc1 == 3 && rc2 == 1 && rc3 == 2)) {
      // Handle card response
   } else if (rc1 == 3 && rc2 == 1 && (rc3 == 3 || rc3 == 4)) {
      // Handle winnings response
   } else {
      // Assuming ASCII response
      char message_buf[8192];
      int i = 0;
      char c = '\0';
      bool saw_newline = false;
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

   return pdu;
};

void listen_to_server(SSL* ssl) {
   for (;;) {
      PDU * p = parse_pdu_client(ssl);
      // Check for ASCII response, valid at any state
      ASCIIResponsePDU* ascii_response_pdu = dynamic_cast<ASCIIResponsePDU*>(p);
      if (ascii_response_pdu) {
         std::cout << "server: " << ascii_response_pdu->getBody();
      }
   }
}

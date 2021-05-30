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
      uint16_t number_of_tables;
      // Read in number of tables
      if ((rc = SSL_read(ssl, &number_of_tables, 2)) <= 0) {
         return pdu;
      }
      number_of_tables = ntohs(number_of_tables);
      std::vector<TabledataPDU*> tabledata;
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
      ASCIIResponsePDU* ar_pdu = dynamic_cast<ASCIIResponsePDU*>(p);
      if (ar_pdu) {
         std::string body = ar_pdu->getBody();
         std::cout << "server message: " << body.substr(0,body.length()-1);
         continue;
      }
      VersionResponsePDU* vr_pdu = dynamic_cast<VersionResponsePDU*>(p);
      if (vr_pdu) {
         std::cout << "server version=" << vr_pdu->getVersion() << std::endl;
         continue;
      }
      BalanceResponsePDU* br_pdu = dynamic_cast<BalanceResponsePDU*>(p);
      if (br_pdu) {
         std::cout << "current balance=" << br_pdu->getBalance() << std::endl;
         continue;
      }
      ListTablesResponsePDU* ltr_pdu = dynamic_cast<ListTablesResponsePDU*>(p);
      if (ltr_pdu) {
         std::vector<TabledataPDU*> tabledata = ltr_pdu->getTabledata();
         for (auto data : tabledata) {
            std::cout << "table ID: " << data->getTableID() << std::endl;
            std::cout << data->getSettings();
         }
         continue;
      }
      AddTableResponsePDU* atr_pdu = dynamic_cast<AddTableResponsePDU*>(p);
      if (atr_pdu) {
         std::cout << "added table, table ID=" << atr_pdu->getTableID() << std::endl;
         continue;
      }
      JoinTableResponsePDU* jtr_pdu = dynamic_cast<JoinTableResponsePDU*>(p);
      if (jtr_pdu) {
         std::string settings = jtr_pdu->getSettings();
         std::cout << "table settings:" << std::endl;
         std::cout << settings;
         continue;
      }
      CardHandResponsePDU* chr_pdu = dynamic_cast<CardHandResponsePDU*>(p);
      if (chr_pdu) {
         std::cout << "holder=";
         if (chr_pdu->getHolder()) {
            std::cout << "you";
         } else {
            std::cout << "dealer";
         }
         std::cout << ", soft value=" << chr_pdu->getSoftValue() << ", hard value=" << chr_pdu->getHardValue() << std::endl;
         std::cout << "Cards:";
         std::vector<CardPDU*> cards = chr_pdu->getCards();
         for (auto card : cards) {
            std::cout << " " << card->getRank() << card->getSuit();
         }
         std::cout << std::endl;
         continue;
      }
      WinningsResponsePDU* wr_pdu = dynamic_cast<WinningsResponsePDU*>(p);
      if (wr_pdu) {
         std::cout << "winnings=" << wr_pdu->getWinnings() << std::endl;
         continue;
      }
   }
}

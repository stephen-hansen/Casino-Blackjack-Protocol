#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <cstring>
#include <string>

#pragma pack(push, 1)

struct Header {
   uint8_t category_code;
   uint8_t command_code;
};

struct Version {
   uint8_t category_code;
   uint8_t command_code;
   uint32_t version;
};

struct UpdateBalance {
   uint8_t category_code;
   uint8_t command_code;
   uint32_t funds;
};

struct RemoveTable {
   uint8_t category_code;
   uint8_t command_code;
   uint16_t table_id;
};

struct JoinTable {
   uint8_t category_code;
   uint8_t command_code;
   uint16_t table_id;
};

struct Bet {
   uint8_t category_code;
   uint8_t command_code;
   uint32_t bet_amount;
};

struct Insurance {
   uint8_t category_code;
   uint8_t command_code;
   uint8_t accept;
};

struct ResponseHeader {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
};

struct VersionResponse {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint32_t version;
};

struct BalanceResponse {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint32_t balance;
};

struct ListTablesResponseHeader {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint16_t number_of_tables;
};

struct AddTableResponse {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint16_t table_id;
};

struct CardHandResponse {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint8_t holder;
   uint8_t soft_value;
   uint8_t hard_value;
   uint8_t number_of_cards;
};

struct WinningsResponse {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint32_t winnings;
};
#pragma pack(pop)

class PDU
{
   public:
      virtual ssize_t to_bytes(char** buf) = 0;
      virtual ~PDU(){};
};

class VersionPDU: public PDU
{
   private:
      Version details;
   public:
      VersionPDU(Version v) {
         details = v;
      }
      uint32_t getVersion() {
         return ntohl(details.version); 
      }
      ssize_t to_bytes(char** buf) {
         *buf = reinterpret_cast<char*>(&details);
         return 6;
      }
};

class UserPDU: public PDU
{
   private:
      Header header;
      std::string username;
   public:
      UserPDU(Header h, std::string user) {
         header = h;
         username = user;
      }
      std::string getUsername() {
         return username.substr(0, username.length()-1); // Do not count \n in username 
      }
      ssize_t to_bytes(char** buf) {
         std::string bytes = (char)(header.category_code) + ((char)(header.command_code) + username);
         *buf = const_cast<char*>(bytes.c_str());
         return 2 + username.length();
      }
};

class PassPDU: public PDU
{
   private:
      Header header;
      std::string password;
   public:
      PassPDU(Header h, std::string pass) {
         header = h;
         password = pass;
      }
      std::string getPassword() {
         return password.substr(0, password.length()-1); // Do not count \n in password 
      }
      ssize_t to_bytes(char** buf) {
         std::string bytes = (char)(header.category_code) + ((char)(header.command_code) + password);
         *buf = const_cast<char*>(bytes.c_str());
         return 2 + password.length();
      }
};

class GetBalancePDU: public PDU
{
   private:
      Header header;
   public:
      GetBalancePDU(Header h) {
         header = h;
      }
      ssize_t to_bytes(char** buf) {
         *buf = reinterpret_cast<char*>(&header);
         return 2;
      }
};

class UpdateBalancePDU: public PDU
{
   private:
      UpdateBalance details;
   public:
      UpdateBalancePDU(UpdateBalance u) {
         details = u;
      }
      uint32_t getFunds() {
         return ntohl(details.funds); 
      }
      ssize_t to_bytes(char** buf) {
         *buf = reinterpret_cast<char*>(&details);
         return 6;
      }
};

class QuitPDU: public PDU
{
   private:
      Header header;
   public:
      QuitPDU(Header h) {
         header = h;
      }
      ssize_t to_bytes(char** buf) {
         *buf = reinterpret_cast<char*>(&header);
         return 2;
      }
};

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
         // Successful message ends in \n and is at least 9 char long
         if (c == '\n' && i >= 9) {
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
         // Successful message ends in \n and is at least 9 char long
         if (c == '\n' && i >= 9) {
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

//ParseResponse parse_pdu_client(SSL* ssl, char* buf, size_t buf_len);


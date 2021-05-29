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
      VersionPDU(uint32_t version) {
         details.category_code = 0;
         details.command_code = 0;
         details.version = version;
      }
      uint32_t getVersion() {
         return ntohl(details.version); 
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(Version));
         return sizeof(Version);
      }
};

class UserPDU: public PDU
{
   private:
      Header header;
      std::string username;
   public:
      UserPDU(std::string user) {
         header.category_code = 0;
         header.command_code = 1;
         username = user;
      }
      std::string getUsername() {
         return username.substr(0, username.length()-1); // Do not count \n in username 
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         username.copy(*buf+sizeof(Header), username.length());
         return sizeof(Header) + username.length();
      }
};

class PassPDU: public PDU
{
   private:
      Header header;
      std::string password;
   public:
      PassPDU(std::string pass) {
         header.category_code = 0;
         header.command_code = 2;
         password = pass;
      }
      std::string getPassword() {
         return password.substr(0, password.length()-1); // Do not count \n in password 
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         password.copy(*buf+sizeof(Header), password.length());
         return sizeof(Header) + password.length();
      }
};

class GetBalancePDU: public PDU
{
   private:
      Header header;
   public:
      GetBalancePDU() {
         header.category_code = 0;
         header.command_code = 3;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

class UpdateBalancePDU: public PDU
{
   private:
      UpdateBalance details;
   public:
      UpdateBalancePDU(uint32_t funds) {
         details.category_code = 0;
         details.command_code = 4;
         details.funds = funds;
      }
      uint32_t getFunds() {
         return ntohl(details.funds); 
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(UpdateBalance));
         return sizeof(UpdateBalance);
      }
};

class QuitPDU: public PDU
{
   private:
      Header header;
   public:
      QuitPDU() {
         header.category_code = 0;
         header.command_code = 5;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};


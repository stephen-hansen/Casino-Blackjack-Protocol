#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <cstring>
#include <string>
#include <vector>

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
   int32_t funds;
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

struct Card {
   char rank;
   char suit;
};

struct CardHandResponseHeader {
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
      UpdateBalancePDU(int32_t funds) {
         details.category_code = 0;
         details.command_code = 4;
         details.funds = funds;
      }
      int32_t getFunds() {
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

class GetTablesPDU: public PDU
{
   private:
      Header header;
   public:
      GetTablesPDU() {
         header.category_code = 1;
         header.command_code = 0;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

class AddTablePDU: public PDU
{
   private:
      Header header;
      std::string settings;
   public:
      AddTablePDU(std::string s) {
         header.category_code = 1;
         header.command_code = 1;
         settings = s;
      }
      std::string getSettings() {
         return settings;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         settings.copy(*buf+sizeof(Header), settings.length());
         return sizeof(Header) + settings.length();
      }
};

class RemoveTablePDU: public PDU
{
   private:
      RemoveTable details;
   public:
      RemoveTablePDU(uint16_t tid) {
         details.category_code = 1;
         details.command_code = 2;
         details.table_id = tid;
      }
      uint16_t getTableID() {
         return ntohs(details.table_id); 
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(RemoveTable));
         return sizeof(RemoveTable);
      }
};

class JoinTablePDU: public PDU
{
   private:
      JoinTable details;
   public:
      JoinTablePDU(uint16_t tid) {
         details.category_code = 1;
         details.command_code = 3;
         details.table_id = tid;
      }
      uint16_t getTableID() {
         return ntohs(details.table_id); 
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(JoinTable));
         return sizeof(JoinTable);
      }
};

class LeaveTablePDU: public PDU
{
   private:
      Header header;
   public:
      LeaveTablePDU() {
         header.category_code = 1;
         header.command_code = 4;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

class BetPDU: public PDU
{
   private:
      Bet details;
   public:
      BetPDU(uint32_t amt) {
         details.category_code = 1;
         details.command_code = 5;
         details.bet_amount = amt;
      }
      uint32_t getBetAmount() {
         return ntohl(details.bet_amount); 
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(Bet));
         return sizeof(Bet);
      }
};

class InsurancePDU: public PDU
{
   private:
      Insurance details;
   public:
      InsurancePDU(uint8_t acc) {
         details.category_code = 1;
         details.command_code = 6;
         details.accept = acc;
      }
      uint8_t isAccepted() {
         return details.accept; 
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(Insurance));
         return sizeof(Insurance);
      }
};

class HitPDU: public PDU
{
   private:
      Header header;
   public:
      HitPDU() {
         header.category_code = 1;
         header.command_code = 7;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

class StandPDU: public PDU
{
   private:
      Header header;
   public:
      StandPDU() {
         header.category_code = 1;
         header.command_code = 8;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

class DoubleDownPDU: public PDU
{
   private:
      Header header;
   public:
      DoubleDownPDU() {
         header.category_code = 1;
         header.command_code = 9;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

class SplitPDU: public PDU
{
   private:
      Header header;
   public:
      SplitPDU() {
         header.category_code = 1;
         header.command_code = 10;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

class SurrenderPDU: public PDU
{
   private:
      Header header;
   public:
      SurrenderPDU() {
         header.category_code = 1;
         header.command_code = 11;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

class ChatPDU: public PDU
{
   private:
      Header header;
      std::string message;
   public:
      ChatPDU(std::string m) {
         header.category_code = 1;
         header.command_code = 12;
         message = m;
      }
      std::string getMessage() {
         return message;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         message.copy(*buf+sizeof(Header), message.length());
         return sizeof(Header) + message.length();
      }
};

class ASCIIResponsePDU: public PDU
{
   private:
      ResponseHeader header;
      std::string body;
   public:
      ASCIIResponsePDU(uint8_t rc_1, uint8_t rc_2, uint8_t rc_3, std::string b) {
         header.reply_code_1 = rc_1;
         header.reply_code_2 = rc_2;
         header.reply_code_3 = rc_3;
         body = b;
      }
      uint8_t getReplyCode1() {
         return header.reply_code_1;
      }
      uint8_t getReplyCode2() {
         return header.reply_code_2;
      }
      uint8_t getReplyCode3() {
         return header.reply_code_3;
      }
      std::string getBody() {
         return body;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(ResponseHeader));
         body.copy(*buf+sizeof(ResponseHeader), body.length());
         return sizeof(ResponseHeader) + body.length();
      }
};

class VersionResponsePDU: public PDU
{
   private:
      VersionResponse details;
   public:
      VersionResponsePDU(uint8_t rc_1, uint8_t rc_2, uint8_t rc_3, uint32_t v) {
         details.reply_code_1 = rc_1;
         details.reply_code_2 = rc_2;
         details.reply_code_3 = rc_3;
         details.version = v;
      }
      uint8_t getReplyCode1() {
         return details.reply_code_1;
      }
      uint8_t getReplyCode2() {
         return details.reply_code_2;
      }
      uint8_t getReplyCode3() {
         return details.reply_code_3;
      }
      uint32_t getVersion() {
         return ntohl(details.version);
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(VersionResponse));
         return sizeof(VersionResponse);
      }
};

class BalanceResponsePDU: public PDU
{
   private:
      BalanceResponse details;
   public:
      BalanceResponsePDU(uint8_t rc_1, uint8_t rc_2, uint8_t rc_3, uint32_t b) {
         details.reply_code_1 = rc_1;
         details.reply_code_2 = rc_2;
         details.reply_code_3 = rc_3;
         details.balance = b;
      }
      uint8_t getReplyCode1() {
         return details.reply_code_1;
      }
      uint8_t getReplyCode2() {
         return details.reply_code_2;
      }
      uint8_t getReplyCode3() {
         return details.reply_code_3;
      }
      uint32_t getBalance() {
         return ntohl(details.balance);
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(BalanceResponse));
         return sizeof(BalanceResponse);
      }
};

class TabledataPDU: public PDU
{
   private:
      uint16_t table_id;
      std::string settings;
   public:
      TabledataPDU(uint16_t tid, std::string s) {
         table_id = tid;
         settings = s;
      }
      uint16_t getTableID() {
         return ntohs(table_id);
      }
      std::string getSettings() {
         return settings;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&table_id), sizeof(uint16_t));
         settings.copy(*buf+sizeof(uint16_t), settings.length());
         return sizeof(uint16_t) + settings.length();
      }
};

class ListTablesResponsePDU: public PDU
{
   private:
      ListTablesResponseHeader header;
      std::vector<TabledataPDU*> tabledata;
   public:
      ListTablesResponsePDU(uint8_t rc_1, uint8_t rc_2, uint8_t rc_3, std::vector<TabledataPDU*> td) {
         header.reply_code_1 = rc_1;
         header.reply_code_2 = rc_2;
         header.reply_code_3 = rc_3;
         header.number_of_tables = htons((uint16_t)td.size());
         tabledata = td;
      }
      uint8_t getReplyCode1() {
         return header.reply_code_1;
      }
      uint8_t getReplyCode2() {
         return header.reply_code_2;
      }
      uint8_t getReplyCode3() {
         return header.reply_code_3;
      }
      std::vector<TabledataPDU*> getTabledata() {
         return tabledata;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(ListTablesResponseHeader));
         ssize_t total_len = sizeof(ListTablesResponseHeader);
         for (auto data : tabledata) {
            char* write_at_buf = *buf+total_len;
            total_len += data->to_bytes(&write_at_buf);
         }
         return total_len;
      }
};

class AddTableResponsePDU: public PDU
{
   private:
      AddTableResponse details;
   public:
      AddTableResponsePDU(uint8_t rc_1, uint8_t rc_2, uint8_t rc_3, uint16_t tid) {
         details.reply_code_1 = rc_1;
         details.reply_code_2 = rc_2;
         details.reply_code_3 = rc_3;
         details.table_id = tid;
      }
      uint8_t getReplyCode1() {
         return details.reply_code_1;
      }
      uint8_t getReplyCode2() {
         return details.reply_code_2;
      }
      uint8_t getReplyCode3() {
         return details.reply_code_3;
      }
      uint16_t getTableID() {
         return ntohs(details.table_id);
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(AddTableResponse));
         return sizeof(AddTableResponse);
      }
};

class JoinTableResponsePDU: public PDU
{
   private:
      ResponseHeader header;
      std::string settings;
   public:
      JoinTableResponsePDU(uint8_t rc_1, uint8_t rc_2, uint8_t rc_3, std::string s) {
         header.reply_code_1 = rc_1;
         header.reply_code_2 = rc_2;
         header.reply_code_3 = rc_3;
         settings = s;
      }
      uint8_t getReplyCode1() {
         return header.reply_code_1;
      }
      uint8_t getReplyCode2() {
         return header.reply_code_2;
      }
      uint8_t getReplyCode3() {
         return header.reply_code_3;
      }
      std::string getSettings() {
         return settings;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(ResponseHeader));
         settings.copy(*buf+sizeof(ResponseHeader), settings.length());
         return sizeof(ResponseHeader) + settings.length();
      }
};

class CardPDU: public PDU
{
   private:
      Card card;
   public:
      CardPDU(char rank, char suit) {
         card.rank = rank;
         card.suit = suit;
      }
      char getRank() {
         return card.rank;
      }
      char getSuit() {
         return card.suit;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&card), sizeof(Card));
         return sizeof(Card);
      }
};

class CardHandResponsePDU: public PDU
{
   private:
      CardHandResponseHeader header;
      std::vector<CardPDU*> cards;
   public:
      CardHandResponsePDU(uint8_t rc_1, uint8_t rc_2, uint8_t rc_3, uint8_t holder, uint8_t soft_value, uint8_t hard_value, std::vector<CardPDU*> c) {
         header.reply_code_1 = rc_1;
         header.reply_code_2 = rc_2;
         header.reply_code_3 = rc_3;
         header.holder = holder;
         header.soft_value = soft_value;
         header.hard_value = hard_value;
         header.number_of_cards = (uint8_t)c.size();
         cards = c;
      }
      uint8_t getReplyCode1() {
         return header.reply_code_1;
      }
      uint8_t getReplyCode2() {
         return header.reply_code_2;
      }
      uint8_t getReplyCode3() {
         return header.reply_code_3;
      }
      uint8_t getHolder() {
         return header.holder;
      }
      uint8_t getSoftValue() {
         return header.soft_value;
      }
      uint8_t getHardValue() {
         return header.hard_value;
      }
      std::vector<CardPDU*> getCards() {
         return cards;
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(CardHandResponseHeader));
         ssize_t total_len = sizeof(CardHandResponseHeader);
         for (auto card : cards) {
            char* write_at_buf = *buf+total_len;
            total_len += card->to_bytes(&write_at_buf);
         }
         return total_len;
      }
};

class WinningsResponsePDU: public PDU
{
   private:
      WinningsResponse details;
   public:
      WinningsResponsePDU(uint8_t rc_1, uint8_t rc_2, uint8_t rc_3, uint32_t w) {
         details.reply_code_1 = rc_1;
         details.reply_code_2 = rc_2;
         details.reply_code_3 = rc_3;
         details.winnings = w;
      }
      uint8_t getReplyCode1() {
         return details.reply_code_1;
      }
      uint8_t getReplyCode2() {
         return details.reply_code_2;
      }
      uint8_t getReplyCode3() {
         return details.reply_code_3;
      }
      uint32_t getWinnings() {
         return ntohl(details.winnings);
      }
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(WinningsResponse));
         return sizeof(WinningsResponse);
      }
};


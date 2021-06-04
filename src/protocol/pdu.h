/* Stephen Hansen
 * 6/4/2021
 * CS 544
 *
 * pdu.h
 * Contains all PDU definitions. Each PDU also
 * defines how it is converted from a human-readable
 * class to a stream of bytes.
 */

#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <cstring>
#include <string>
#include <vector>

// I use pragma pack here to ensure there is no byte padding
// in these helper structs.

#pragma pack(push, 1)

// Common header for all client commands
struct Header {
   uint8_t category_code;
   uint8_t command_code;
};

// Structure of VERSION command
struct Version {
   uint8_t category_code;
   uint8_t command_code;
   uint32_t version;
};

// Structure of UPDATE command
struct UpdateBalance {
   uint8_t category_code;
   uint8_t command_code;
   int32_t funds;
};

// Structure of REMOVE command
struct RemoveTable {
   uint8_t category_code;
   uint8_t command_code;
   uint16_t table_id;
};

// Structure of JOIN command
struct JoinTable {
   uint8_t category_code;
   uint8_t command_code;
   uint16_t table_id;
};

// Structure of BET command
struct Bet {
   uint8_t category_code;
   uint8_t command_code;
   uint32_t bet_amount;
};

// Common header for all server responses
struct ResponseHeader {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
};

// Structure of VERSION response
struct VersionResponse {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint32_t version;
};

// Structure of BALANCE response
struct BalanceResponse {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint32_t balance;
};

// Structure of LIST response header
struct ListTablesResponseHeader {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint16_t number_of_tables;
};

// Structure of ADD response
struct AddTableResponse {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint16_t table_id;
};

// Structure of a card
struct Card {
   char rank;
   char suit;
};

// Structure of a card response header
struct CardHandResponseHeader {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint8_t holder;
   uint8_t soft_value;
   uint8_t hard_value;
   uint8_t number_of_cards;
};

// Structure of WINNINGS response
struct WinningsResponse {
   uint8_t reply_code_1;
   uint8_t reply_code_2;
   uint8_t reply_code_3;
   uint32_t winnings;
};
#pragma pack(pop)

// Generic abstract PDU class, PDU must support a way
// to encode to bytes, and a destructor.
class PDU
{
   public:
      // to_bytes fills *buf with the byte encoding
      // and returns the number of bytes filled
      virtual ssize_t to_bytes(char** buf) = 0;
      virtual ~PDU(){};
};

// PDUs sent by CLIENT

// This class represents the VERSION PDU.
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
      // Return the version, convert from big to little endian.
      uint32_t getVersion() {
         return ntohl(details.version); 
      }
      // to_bytes copies the struct form into a buffer
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(Version));
         return sizeof(Version);
      }
};

// This class represents the USER PDU.
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
      // The username is stored as a std::string ending in \n
      std::string getUsername() {
         return username.substr(0, username.length()-1); // Do not count \n in username 
      }
      // to_bytes copies the header, then copies over the entire username
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         username.copy(*buf+sizeof(Header), username.length());
         return sizeof(Header) + username.length();
      }
};

// This class represents the PASS PDU.
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
      // The password is stored as a std::string ending in \n
      std::string getPassword() {
         return password.substr(0, password.length()-1); // Do not count \n in password 
      }
      // to_bytes copies the header, then copies over the entire password
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         password.copy(*buf+sizeof(Header), password.length());
         return sizeof(Header) + password.length();
      }
};

// This class represents the GETBALANCE PDU
class GetBalancePDU: public PDU
{
   private:
      Header header;
   public:
      GetBalancePDU() {
         header.category_code = 0;
         header.command_code = 3;
      }
      // to_bytes copies over the header
      // GetBalance is just a specific header value
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

// This class represents the UPDATEBALANCE PDU
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
      // The funds are converted from big endian to little endian
      int32_t getFunds() {
         return ntohl(details.funds); 
      }
      // to_bytes copies over the struct form
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(UpdateBalance));
         return sizeof(UpdateBalance);
      }
};

// This class represents the QUIT PDU
class QuitPDU: public PDU
{
   private:
      Header header;
   public:
      QuitPDU() {
         header.category_code = 0;
         header.command_code = 5;
      }
      // to_bytes copies over the header, QUIT has a specific header value
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

// This class represents the GETTABLES PDU
class GetTablesPDU: public PDU
{
   private:
      Header header;
   public:
      GetTablesPDU() {
         header.category_code = 1;
         header.command_code = 0;
      }
      // to_bytes copies over the header, GETTABLES has a specific header value
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

// This class represents the ADDTABLE PDU
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
      // The settings string is the table settings, as std::string, ending in \n\n
      std::string getSettings() {
         return settings;
      }
      // to_bytes copies over the header, then copies over the settings string at the end
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         settings.copy(*buf+sizeof(Header), settings.length());
         return sizeof(Header) + settings.length();
      }
};

// This class represents the REMOVETABLE PDU
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
      // Return the table ID as little endian (from big endian)
      uint16_t getTableID() {
         return ntohs(details.table_id); 
      }
      // to_bytes copies over the struct form
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(RemoveTable));
         return sizeof(RemoveTable);
      }
};

// This class represents the JOINTABLE PDU
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
      // Return the table ID as little endian (from big endian)
      uint16_t getTableID() {
         return ntohs(details.table_id); 
      }
      // to_bytes copies over the struct form
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(JoinTable));
         return sizeof(JoinTable);
      }
};

// This class represents the LEAVETABLE PDU
class LeaveTablePDU: public PDU
{
   private:
      Header header;
   public:
      LeaveTablePDU() {
         header.category_code = 1;
         header.command_code = 4;
      }
      // to_bytes copies over the header, which has a specific value for LEAVETABLE
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

// This class represents the BET PDU
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
      // Return bet amount, from big endian to little endian
      uint32_t getBetAmount() {
         return ntohl(details.bet_amount); 
      }
      // to_bytes copies over the struct form
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(Bet));
         return sizeof(Bet);
      }
};

// This class represents the HIT PDU
class HitPDU: public PDU
{
   private:
      Header header;
   public:
      HitPDU() {
         header.category_code = 1;
         header.command_code = 7;
      }
      // to_bytes copies over the header, which has a specific value for HIT
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

// This class represents the STAND PDU
class StandPDU: public PDU
{
   private:
      Header header;
   public:
      StandPDU() {
         header.category_code = 1;
         header.command_code = 8;
      }
      // to_bytes copies over the header, which has a specific value for STAND
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

// This class represents the DOUBLEDOWN PDU
class DoubleDownPDU: public PDU
{
   private:
      Header header;
   public:
      DoubleDownPDU() {
         header.category_code = 1;
         header.command_code = 9;
      }
      // to_bytes copies over the header, which has a specific value for DOUBLEDOWN
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         return sizeof(Header);
      }
};

// This class represents the CHAT PDU
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
      // Return the chat message, ASCII std::string ending in \n
      std::string getMessage() {
         return message;
      }
      // to_bytes copies over the header, and then after the entire message
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(Header));
         message.copy(*buf+sizeof(Header), message.length());
         return sizeof(Header) + message.length();
      }
};

// PDUs sent by SERVER

// ASCIIResponsePDU represents a response with an ASCII message. This
// is the most common type of response.
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
      // The body is the ASCII message sent in the PDU.
      std::string getBody() {
         return body;
      }
      // to_bytes copies over a response header, then the ASCII message
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(ResponseHeader));
         body.copy(*buf+sizeof(ResponseHeader), body.length());
         return sizeof(ResponseHeader) + body.length();
      }
};

// VersionResponsePDU represents the response to a VERSION command.
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
      // Convert version from big endian to little endian
      uint32_t getVersion() {
         return ntohl(details.version);
      }
      // to_bytes copies over the struct form
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(VersionResponse));
         return sizeof(VersionResponse);
      }
};

// BalanceResponsePDU represents a successful response to the BALANCE command
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
      // Convert balance from big endian to little endian
      uint32_t getBalance() {
         return ntohl(details.balance);
      }
      // to_bytes copies over the struct form
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(BalanceResponse));
         return sizeof(BalanceResponse);
      }
};

// TabledataPDU is a helper PDU that represents data for a single table.
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
      // Convert table ID from big endian to little endian
      uint16_t getTableID() {
         return ntohs(table_id);
      }
      // settings is an ASCII string detailing table configuration, ends in \n\n
      std::string getSettings() {
         return settings;
      }
      // to_bytes copies over the table ID, then the entire settings string
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&table_id), sizeof(uint16_t));
         settings.copy(*buf+sizeof(uint16_t), settings.length());
         return sizeof(uint16_t) + settings.length();
      }
};

// ListTablesResponsePDU is a response PDU to the GETTABLES command.
// It holds many Tabledata PDUs inside.
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
         header.number_of_tables = htons((uint16_t)td.size()); // Number of tables must be big endian
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
      // Return a std::vector of tabledata PDUs to iterate through
      std::vector<TabledataPDU*> getTabledata() {
         return tabledata;
      }
      // to_bytes copies the header over, then writes each tabledata PDU after the
      // header at the latest offset.
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(ListTablesResponseHeader));
         ssize_t total_len = sizeof(ListTablesResponseHeader);
         for (auto data : tabledata) {
            char* write_at_buf = *buf+total_len; // Offset at which to write table settings
            total_len += data->to_bytes(&write_at_buf); // Write tabledata at offset
         }
         return total_len;
      }
};

// AddTableResponsePDU is a successful response to an ADDTABLE command.
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
      // Convert table ID from big endian to little endian.
      uint16_t getTableID() {
         return ntohs(details.table_id);
      }
      // to_bytes copies over the struct form
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(AddTableResponse));
         return sizeof(AddTableResponse);
      }
};

// JoinTableResponsePDU is a successful response to a JOINTABLE command.
// Includes the table settings within the response.
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
      // Return the settings for the table just joined, ASCII string ending in \n\n
      std::string getSettings() {
         return settings;
      }
      // to_bytes copies over the response header, then the settings string
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(ResponseHeader));
         settings.copy(*buf+sizeof(ResponseHeader), settings.length());
         return sizeof(ResponseHeader) + settings.length();
      }
};

// CardPDU contains data for a single card. This is a helper PDU.
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
      // to_bytes copies over the card struct (rank, suit 1 byte each)
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&card), sizeof(Card));
         return sizeof(Card);
      }
};

// CardHandResponsePDU contains detail for a hand. Includes
// detail about the owner, soft value, hard value, and cards.
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
      // Return a vector of cards representing the hand
      std::vector<CardPDU*> getCards() {
         return cards;
      }
      // to_bytes writes the response header, then copies over each card after
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&header), sizeof(CardHandResponseHeader));
         ssize_t total_len = sizeof(CardHandResponseHeader);
         for (auto card : cards) {
            char* write_at_buf = *buf+total_len; // Get the offset for the next card
            total_len += card->to_bytes(&write_at_buf); // Write the card to the buffer
         }
         return total_len;
      }
};

// WinningsResponsePDU details a PDU that sends the total amount of funds won in a game.
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
      // Convert winnings from big endian to little endian
      uint32_t getWinnings() {
         return ntohl(details.winnings);
      }
      // to_bytes copies over the struct form
      ssize_t to_bytes(char** buf) {
         memcpy((void*)*buf, reinterpret_cast<void*>(&details), sizeof(WinningsResponse));
         return sizeof(WinningsResponse);
      }
};


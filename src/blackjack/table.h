#include <mutex>
#include <vector>

#include "../protocol/pdu.h"

class TableDetails
{
   private:
      std::mutex mtx;
      std::vector<SSL*> players;
      std::vector<SSL*> pending_players;
   public:
      TableDetails() {}
};

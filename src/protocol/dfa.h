/* Stephen Hansen
 * 6/4/2021
 * CS 544
 *
 * dfa.h
 * Contains an enumeration representing the various game states.
 */


// STATE is the enumeration of all states as defined by the protocol.
// At any moment the conversation between a client and server may
// only be in one of these given states.
// STATEFUL
enum STATE {
   VERSION,
   USERNAME,
   PASSWORD,
   ACCOUNT,
   IN_PROGRESS,
   ENTER_BETS,
   WAIT_FOR_TURN,
   TURN,
   WAIT_FOR_DEALER,
};


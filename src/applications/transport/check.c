
/**
 * Transport Session handle.
 */
typedef struct TCPSession
{

  struct TCPSession *next;

  /**
   * the tcp socket (used to identify this connection with selector)
   */
  struct SocketHandle *sock;

  /**
   * Our tsession.
   */
  TSession *tsession;

  /**
   * mutex for synchronized access to 'users'
   */
  struct MUTEX *lock;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  PeerIdentity sender;

  /**
   * Are we still expecting the welcome? (YES/NO)
   */
  int expectingWelcome;

  /**
   * number of users of this session (reference count)
   */
  int users;

  /**
   * Is this session active with select?
   */
  int in_select;

  void *accept_addr;

  unsigned int addr_len;

} TCPSession;

static void
check (TSession * session)
{
  TCPSession *tcp;

  if (session->ttype != TCP_PROTOCOL_NUMBER)
    return;
  tcp = session->internal;
  GE_ASSERT (NULL, tcp->users >= session->token_count);
}

#define CHECK(s) check(s)

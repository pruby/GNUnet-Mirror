
#include "gnunet_util.h"
#include "platform.h"

/**
 * TIME prototype. "man time".
 */
TIME_T TIME(TIME_T * t) {
  TIME_T now;

  now = (TIME_T) time(NULL); /* potential 64-bit to 32-bit conversion!*/
  if (t != NULL)
    *t = now;
  return now;
}

/**
 * "man ctime_r".  Automagically expands the 32-bit
 * GNUnet time value to a 64-bit value of the current
 * epoc if needed.
 */
char * GN_CTIME(const TIME_T * t) {
  TIME_T now;
  time_t tnow;

  tnow = time(NULL);
  now = (TIME_T) tnow;
  tnow = tnow - now + *t;
#ifdef ctime_r
  return ctime_r(&tnow, MALLOC(32));
#else
  return STRDUP(ctime(&tnow));
#endif
}

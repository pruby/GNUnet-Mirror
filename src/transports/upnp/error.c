
#include "error.h"

/**
 * Map gaim logger to GNUnet logger.
 */
void
gaim_debug_error (char *facility, char *format, ...)
{
  GNUNET_GE_LOG (NULL,
                 GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER | GNUNET_GE_ADMIN |
                 GNUNET_GE_BULK, "%s: %s\n", facility, format);
}

/**
 * Map gaim logger to GNUnet logger.
 */
void
gaim_debug_info (char *facility, char *format, ...)
{
  GNUNET_GE_LOG (NULL, GNUNET_GE_INFO | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                 "%s: %s\n", facility, format);
}

/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file src/util/loggers/smtp.c
 * @brief logging via email
 * @author Christian Grothoff
 */
#include "gnunet_util_error_loggers.h"

#if FICTION
/**
 * @param address e-mail address to send the logs to
 * @param server hostname of SMTP gateway, NULL for using local "mail" command
 * @param port port to use for SMTP
 * @param logDate should the date be each of the log lines?
 * @param bulkSize for GNUNET_GE_BULK messages, how many lines of messages
 *        should be accumulated before an e-mail is transmitted?
 */
struct GNUNET_GE_Context *
GNUNET_GE_create_context_email (struct GNUNET_GE_Context *ectx,
                                GNUNET_GE_MASK mask,
                                const char *address,
                                const char *server,
                                unsigned short port,
                                int logDate, unsigned int bulkSize)
{
  return NULL;
}

#endif

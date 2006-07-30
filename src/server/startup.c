/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file server/startup.c
 * @brief insignificant gnunetd helper methods
 *
 * Helper methods for the startup of gnunetd:
 * - PID file handling
 *
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"

#include "tcpserver.h"
#include "core.h"
#include "startup.h"

int changeUser(struct GE_Context * ectx,
	       struct GC_Configuration * cfg) {
  char * user;

  user = NULL;
  if (0 == GC_get_configuration_value_string(cfg,
					     "GNUNETD",
					     "USER",
					     NULL,
					     &user)) {
    if (OK != os_change_user(ectx,
			     user)) {
      FREE(user);
      return SYSERR;
    }
    FREE(user);
  }
  return OK;
}


static char * getPIDFile(struct GC_Configuration * cfg) {
  char * pif;
  
  if (0 != GC_get_configuration_value_string(cfg,
					     "GNUNETD",
					     "PIDFILE",
					     NULL,
					     &pif))
    return NULL;
  return pif;
}

/**
 * Write our process ID to the pid file.
 */
void writePIDFile(struct GE_Context * ectx,
		  struct GC_Configuration * cfg) {
  FILE * pidfd;
  char * pif;

  pif = getPIDFile(cfg);
  if (pif == NULL)
    return; /* no PID file */
  pidfd = FOPEN(pif, "w");
  if (pidfd == NULL) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_ADMIN | GE_BULK,
			 "fopen",
			 pif);
    return;
  }
  if (0 > FPRINTF(pidfd, 
		  "%u", 
		  (unsigned int) getpid())) 
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_ADMIN | GE_BULK,
			 "fprintf",
			 pif);    
  if (0 != fclose(pidfd))
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_ADMIN | GE_BULK,
			 "fclose",
			 pif); 
  FREE(pif);
}

void deletePIDFile(struct GE_Context * ectx,
		   struct GC_Configuration * cfg) {
  char * pif = getPIDFile(cfg);
  if (pif == NULL)
    return; /* no PID file */
  if (0 != UNLINK(pif))
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_ADMIN | GE_BULK,
			 "unlink",
			 pif);
  FREE(pif);
}

/* end of startup.c */

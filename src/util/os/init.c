/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/os/init.c
 * @brief functions to initialize os specifics
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"

/**
 * @brief Perform OS specific initalization
 * @param ectx logging context, NULL means stderr
 * @returns OK on success, SYSERR otherwise
 */
int
os_init (struct GE_Context *ectx)
{
#ifdef MINGW
  if (InitWinEnv (ectx) != ERROR_SUCCESS)
    return SYSERR;
  else
#endif
    return OK;
}

/**
 * @brief Perform OS specific cleanup
 */
void __attribute__ ((destructor)) os_fini ()
{
#ifdef MINGW
  ShutdownWinEnv ();
#endif
}

/* end of init.c */

/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file util/crypto/locking_gcrypt.c
 * @brief locking for gcrypt
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "locking_gcrypt.h"
#include <gcrypt.h>

/**
 * Should we use a lock to avoid concurrent accesses
 * to gcrypt or should we tell gcrypt that we use
 * pthreads?
 */
#define USE_LOCK NO

#if USE_LOCK
static struct MUTEX *gcrypt_shared_lock;
#else
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif


void
lockGcrypt ()
{
#if USE_LOCK
  MUTEX_LOCK (gcrypt_shared_lock);
#endif
}

void
unlockGcrypt ()
{
#if USE_LOCK
  MUTEX_UNLOCK (gcrypt_shared_lock);
#endif
}

static void
dummy_logger (void *arg, int level, const char *format, va_list args)
{
  /* do nothing -- ignore libgcyrpt errors */
}

void __attribute__ ((constructor)) gnunet_crypto_ltdl_init ()
{
#if USE_LOCK
  gcrypt_shared_lock = MUTEX_CREATE (YES);
#else
  gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#endif
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version (GCRYPT_VERSION))
    {
      fprintf (stderr,
               _
               ("libgcrypt has not the expected version (version %s is required).\n"),
               GCRYPT_VERSION);
      abort ();
    }
  srand ((unsigned int) time (NULL));
  gcry_set_log_handler (&dummy_logger, NULL);
#ifdef gcry_fast_random_poll
  lockGcrypt ();
  gcry_fast_random_poll ();
  unlockGcrypt ();
#endif
}

void __attribute__ ((destructor)) gnunet_crypto_ltdl_fini ()
{
#if USE_LOCK
  MUTEX_DESTROY (gcrypt_shared_lock);
  gcrypt_shared_lock = NULL;
#endif
}

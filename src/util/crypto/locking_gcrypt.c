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
#define USE_LOCK GNUNET_NO

#if USE_LOCK
static struct GNUNET_Mutex *gcrypt_shared_lock;
#else
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif


void
GNUNET_lock_gcrypt_ ()
{
#if USE_LOCK
  GNUNET_mutex_lock (gcrypt_shared_lock);
#endif
}

void
GNUNET_unlock_gcrypt_ ()
{
#if USE_LOCK
  GNUNET_mutex_unlock (gcrypt_shared_lock);
#endif
}

static void
dummy_logger (void *arg, int level, const char *format, va_list args)
{
  /* do nothing -- ignore libgcyrpt errors */
}

void __attribute__ ((constructor)) GNUNET_crypto_ltdl_init ()
{
#if USE_LOCK
  gcrypt_shared_lock = GNUNET_mutex_create (GNUNET_YES);
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
  GNUNET_lock_gcrypt_ ();
  gcry_fast_random_poll ();
  GNUNET_unlock_gcrypt_ ();
#endif
}

/**
 * This function should only be called in testcases
 * where strong entropy gathering is not desired
 * (for example, for hostkey generation).
 */
void
GNUNET_disable_entropy_gathering ()
{
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
}


void __attribute__ ((destructor)) GNUNET_crypto_ltdl_fini ()
{
#if USE_LOCK
  GNUNET_mutex_destroy (gcrypt_shared_lock);
  gcrypt_shared_lock = NULL;
#endif
}

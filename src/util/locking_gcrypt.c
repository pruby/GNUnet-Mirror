/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file util/locking_gcrypt.c
 * @brief locking for gcrypt
 * @author Christian Grothoff
 */

#include "gnunet_util.h"

static Mutex gcrypt_shared_lock;

void lockGcrypt() {
  MUTEX_LOCK(&gcrypt_shared_lock);  
}

void unlockGcrypt() {
  MUTEX_UNLOCK(&gcrypt_shared_lock);  
}

void initLockingGcrypt() {
  MUTEX_CREATE_RECURSIVE(&gcrypt_shared_lock);
}

void doneLockingGcrypt() {
  MUTEX_DESTROY(&gcrypt_shared_lock);
}

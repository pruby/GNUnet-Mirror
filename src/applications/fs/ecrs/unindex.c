/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/unindex.c
 * @author Krista Bennett
 * @author Christian Grothoff
 *
 * Unindex file.
 *
 * TODO:
 * - code cleanup (share more with upload.c)
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "gnunet_getoption_lib.h"
#include "ecrs_core.h"
#include "ecrs.h"
#include "fs.h"
#include "tree.h"

#define STRICT_CHECKS GNUNET_NO

/**
 * Append the given key and query to the iblock[level].
 * If iblock[level] is already full, compute its chk
 * and push it to level+1.  iblocks is guaranteed to
 * be big enough.
 *
 * This function matches exactly upload.c::pushBlock,
 * except in the call to 'FS_delete'.  TODO: refactor
 * to avoid code duplication (move to block.c, pass
 * FS_delete as argument!).
 */
static int
pushBlock (struct GNUNET_ClientServerConnection *sock,
           const CHK * chk, unsigned int level, Datastore_Value ** iblocks)
{
  unsigned int size;
  unsigned int present;
  Datastore_Value *value;
  DBlock *db;
  CHK ichk;

  size = ntohl (iblocks[level]->size) - sizeof (Datastore_Value);
  present = (size - sizeof (DBlock)) / sizeof (CHK);
  db = (DBlock *) & iblocks[level][1];
  if (present == CHK_PER_INODE)
    {
      fileBlockGetKey (db, size, &ichk.key);
      fileBlockGetQuery (db, size, &ichk.query);
      if (GNUNET_OK != pushBlock (sock, &ichk, level + 1, iblocks))
        {
          GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      fileBlockEncode (db, size, &ichk.query, &value);
#if STRICT_CHECKS
      if (GNUNET_SYSERR == FS_delete (sock, value))
        {
          GNUNET_free (value);
          GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
#else
      FS_delete (sock, value);
#endif
      GNUNET_free (value);
      size = sizeof (DBlock);
    }
  /* append CHK */
  memcpy (&((char *) db)[size], chk, sizeof (CHK));
  iblocks[level]->size = htonl (size +
                                sizeof (CHK) + sizeof (Datastore_Value));
  return GNUNET_OK;
}



/**
 * Undo sym-linking operation:
 * a) check if we have a symlink
 * b) delete symbolic link
 */
static int
undoSymlinking (struct GE_Context *ectx,
                const char *fn,
                const GNUNET_HashCode * fileId,
                struct GNUNET_ClientServerConnection *sock)
{
  GNUNET_EncName enc;
  char *serverDir;
  char *serverFN;
  struct stat buf;

#ifndef S_ISLNK
  if (1)
    return GNUNET_OK;           /* symlinks do not exist? */
#endif
  if (0 != LSTAT (fn, &buf))
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_ERROR | GE_BULK | GE_USER | GE_ADMIN,
                            "stat", fn);
      return GNUNET_SYSERR;
    }
#ifdef S_ISLNK
  if (!S_ISLNK (buf.st_mode))
    return GNUNET_OK;
#endif
  serverDir = GNUNET_get_daemon_configuration_value (sock, "FS", "INDEX-DIRECTORY");
  if (serverDir == NULL)
    return GNUNET_OK;
  serverFN = GNUNET_malloc (strlen (serverDir) + 2 + sizeof (GNUNET_EncName));
  strcpy (serverFN, serverDir);
  GNUNET_free (serverDir);
  if (serverFN[strlen (serverFN) - 1] != DIR_SEPARATOR)
    strcat (serverFN, DIR_SEPARATOR_STR);
  GNUNET_hash_to_enc (fileId, &enc);
  strcat (serverFN, (char *) &enc);

  if (0 != UNLINK (serverFN))
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_ERROR | GE_BULK | GE_USER | GE_ADMIN,
                            "unlink", serverFN);
      GNUNET_free (serverFN);
      return GNUNET_SYSERR;
    }
  GNUNET_free (serverFN);
  return GNUNET_OK;
}



/**
 * Unindex a file.
 *
 * @return GNUNET_SYSERR if the unindexing failed (i.e. not indexed)
 */
int
ECRS_unindexFile (struct GE_Context *ectx,
                  struct GC_Configuration *cfg,
                  const char *filename,
                  ECRS_UploadProgressCallback upcb,
                  void *upcbClosure, ECRS_TestTerminate tt, void *ttClosure)
{
  unsigned long long filesize;
  unsigned long long pos;
  unsigned int treedepth;
  int fd;
  int i;
  unsigned int size;
  Datastore_Value **iblocks;
  Datastore_Value *dblock;
  DBlock *db;
  Datastore_Value *value;
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_HashCode fileId;
  CHK chk;
  GNUNET_CronTime eta;
  GNUNET_CronTime start;
  GNUNET_CronTime now;
  int wasIndexed;

  start = GNUNET_get_time ();
  if (GNUNET_YES != GNUNET_disk_file_test (ectx, filename))
    {
      GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK !=
      GNUNET_disk_file_size (ectx, filename, &filesize, GNUNET_YES))
    return GNUNET_SYSERR;
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    return GNUNET_SYSERR;
  eta = 0;
  if (upcb != NULL)
    upcb (filesize, 0, eta, upcbClosure);
  if (GNUNET_SYSERR == GNUNET_hash_file (ectx, filename, &fileId))
    {
      GNUNET_client_connection_destroy (sock);
      GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  now = GNUNET_get_time ();
  eta = now + 2 * (now - start);
  /* very rough estimate: GNUNET_hash reads once through the file,
     we'll do that once more and write it.  But of course
     the second read may be cached, and we have the encryption,
     so a factor of two is really, really just a rough estimate */
  start = now;
  /* reset the counter since the formula later does not
     take the time for GNUNET_hash_file into account */
  treedepth = computeDepth (filesize);

  /* Test if file is indexed! */
  wasIndexed = FS_testIndexed (sock, &fileId);

  fd = GNUNET_disk_file_open (ectx, filename, O_RDONLY | O_LARGEFILE);
  if (fd == -1)
    return GNUNET_SYSERR;
  dblock =
    GNUNET_malloc (sizeof (Datastore_Value) + DBLOCK_SIZE + sizeof (DBlock));
  dblock->size =
    htonl (sizeof (Datastore_Value) + DBLOCK_SIZE + sizeof (DBlock));
  dblock->anonymityLevel = htonl (0);
  dblock->prio = htonl (0);
  dblock->type = htonl (D_BLOCK);
  dblock->expirationTime = GNUNET_htonll (0);
  db = (DBlock *) & dblock[1];
  db->type = htonl (D_BLOCK);
  iblocks = GNUNET_malloc (sizeof (Datastore_Value *) * (treedepth + 1));
  for (i = 0; i <= treedepth; i++)
    {
      iblocks[i] =
        GNUNET_malloc (sizeof (Datastore_Value) + IBLOCK_SIZE +
                       sizeof (DBlock));
      iblocks[i]->size = htonl (sizeof (Datastore_Value) + sizeof (DBlock));
      iblocks[i]->anonymityLevel = htonl (0);
      iblocks[i]->prio = htonl (0);
      iblocks[i]->type = htonl (D_BLOCK);
      iblocks[i]->expirationTime = GNUNET_htonll (0);
      ((DBlock *) & iblocks[i][1])->type = htonl (D_BLOCK);
    }

  pos = 0;
  while (pos < filesize)
    {
      if (upcb != NULL)
        upcb (filesize, pos, eta, upcbClosure);
      if (tt != NULL)
        if (GNUNET_OK != tt (ttClosure))
          goto FAILURE;
      size = DBLOCK_SIZE;
      if (size > filesize - pos)
        {
          size = filesize - pos;
          memset (&db[1], 0, DBLOCK_SIZE);
        }
      dblock->size =
        htonl (sizeof (Datastore_Value) + size + sizeof (DBlock));
      if (size != READ (fd, &db[1], size))
        {
          GE_LOG_STRERROR_FILE (ectx,
                                GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
                                "READ", filename);
          goto FAILURE;
        }
      if (tt != NULL)
        if (GNUNET_OK != tt (ttClosure))
          goto FAILURE;
      fileBlockGetKey (db, size + sizeof (DBlock), &chk.key);
      fileBlockGetQuery (db, size + sizeof (DBlock), &chk.query);
      if (GNUNET_OK != pushBlock (sock, &chk, 0,        /* dblocks are on level 0 */
                                  iblocks))
        {
          GE_BREAK (ectx, 0);
          goto FAILURE;
        }
      if (!wasIndexed)
        {
          if (GNUNET_OK == fileBlockEncode (db, size, &chk.query, &value))
            {
              *value = *dblock; /* copy options! */
#if STRICT_CHECKS
              if (GNUNET_OK != FS_delete (sock, value))
                {
                  GNUNET_free (value);
                  GE_BREAK (ectx, 0);
                  goto FAILURE;
                }
#else
              FS_delete (sock, value);
#endif
              GNUNET_free (value);
            }
          else
            {
              goto FAILURE;
            }
        }
      pos += size;
      now = GNUNET_get_time ();
      eta = (GNUNET_CronTime) (start +
                               (((double) (now - start) / (double) pos))
                               * (double) filesize);
    }
  if (tt != NULL)
    if (GNUNET_OK != tt (ttClosure))
      goto FAILURE;
  for (i = 0; i < treedepth; i++)
    {
      size = ntohl (iblocks[i]->size) - sizeof (Datastore_Value);
      db = (DBlock *) & iblocks[i][1];
      fileBlockGetKey (db, size, &chk.key);
      fileBlockGetQuery (db, size, &chk.query);
      if (GNUNET_OK != pushBlock (sock, &chk, i + 1, iblocks))
        {
          GE_BREAK (ectx, 0);
          goto FAILURE;
        }
      fileBlockEncode (db, size, &chk.query, &value);
#if STRICT_CHECKS
      if (GNUNET_OK != FS_delete (sock, value))
        {
          GNUNET_free (value);
          GE_BREAK (ectx, 0);
          goto FAILURE;
        }
#else
      FS_delete (sock, value);
#endif
      GNUNET_free (value);
      GNUNET_free (iblocks[i]);
      iblocks[i] = NULL;
    }

  if (wasIndexed)
    {
      if (GNUNET_OK == undoSymlinking (ectx, filename, &fileId, sock))
        {
          if (GNUNET_OK != FS_unindex (sock, DBLOCK_SIZE, &fileId))
            {
              GE_BREAK (ectx, 0);
              goto FAILURE;
            }
        }
      else
        {
          GE_BREAK (ectx, 0);
          goto FAILURE;
        }
    }
  GNUNET_free (iblocks[treedepth]);
  /* free resources */
  GNUNET_free (iblocks);
  GNUNET_free (dblock);
  CLOSE (fd);
  GNUNET_client_connection_destroy (sock);
  return GNUNET_OK;
FAILURE:
  for (i = 0; i <= treedepth; i++)
    GNUNET_free_non_null (iblocks[i]);
  GNUNET_free (iblocks);
  GNUNET_free (dblock);
  CLOSE (fd);
  GNUNET_client_connection_destroy (sock);
  return GNUNET_SYSERR;
}

/* end of unindex.c */

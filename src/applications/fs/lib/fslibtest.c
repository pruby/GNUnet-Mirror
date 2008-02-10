/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/lib/fslibtest.c
 * @brief testcase for fslib
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fs_lib.h"
#include "gnunet_protocols.h"
#include "ecrs_core.h"


#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(NULL, 0); goto FAILURE; }

static struct GNUNET_CronManager *cron;

static GNUNET_CronTime now;

static struct GNUNET_ThreadHandle *mainThread;

static struct GNUNET_Mutex *lock;

static struct GNUNET_GC_Configuration *cfg;


static GNUNET_DatastoreValue *
makeBlock (int i)
{
  GNUNET_DatastoreValue *block;
  DBlock *db;

  block =
    GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + sizeof (DBlock) + i);
  block->size = htonl (sizeof (GNUNET_DatastoreValue) + sizeof (DBlock) + i);
  block->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
  block->prio = htonl (0);
  block->anonymityLevel = htonl (0);
  block->expirationTime = GNUNET_htonll (now + 1 * GNUNET_CRON_HOURS);
  db = (DBlock *) & block[1];
  db->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
  memset (&db[1], i + (i / 253), i);
  return block;
}

static GNUNET_DatastoreValue *
makeKBlock (unsigned int i, const GNUNET_HashCode * key,
            GNUNET_HashCode * query)
{
  GNUNET_DatastoreValue *block;
  KBlock *db;
  struct GNUNET_RSA_PrivateKey *kkey;

  block =
    GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + sizeof (KBlock) + i);
  block->size = htonl (sizeof (GNUNET_DatastoreValue) + sizeof (KBlock) + i);
  block->type = htonl (GNUNET_ECRS_BLOCKTYPE_KEYWORD);
  block->prio = htonl (0);
  block->anonymityLevel = htonl (0);
  block->expirationTime = GNUNET_htonll (now + 1 * GNUNET_CRON_HOURS);
  db = (KBlock *) & block[1];
  db->type = htonl (GNUNET_ECRS_BLOCKTYPE_KEYWORD);
  memset (&db[1], i + (i / 253), i);
  kkey = GNUNET_RSA_create_key_from_hash (key);
  GNUNET_RSA_sign (kkey, i, &db[1], &db->signature);
  GNUNET_RSA_get_public_key (kkey, &db->keyspace);
  GNUNET_hash (&db->keyspace, sizeof (GNUNET_RSA_PublicKey), query);
  GNUNET_RSA_free_key (kkey);
  return block;
}


typedef struct
{
  struct GNUNET_Semaphore *sem;
  int found;
  int i;
} TSC;

static void
abortSem (void *cls)
{
  struct GNUNET_Semaphore *sem = cls;
  GNUNET_semaphore_up (sem);
}

/**
 * Search result callback that just counts down
 * a counter.
 */
static int
countCallback (const GNUNET_HashCode * key,
               const GNUNET_DatastoreValue * value, void *cls,
               unsigned long long uid)
{
  int *cnt = cls;
  (*cnt)--;
  fprintf (stderr, "*");
  if (*cnt <= 0)
    GNUNET_thread_stop_sleep (mainThread);
  return GNUNET_OK;
}


static int
searchResultCB (const GNUNET_HashCode * key,
                const GNUNET_DatastoreValue * value, void *ctx,
                unsigned long long uid)
{
  TSC *cls = ctx;
  GNUNET_HashCode ekey;
  GNUNET_DatastoreValue *blk;
  GNUNET_DatastoreValue *eblk;
  int ret;

  blk = makeBlock (cls->i);
  GNUNET_EC_file_block_get_query ((DBlock *) & blk[1],
                                  ntohl (blk->size) -
                                  sizeof (GNUNET_DatastoreValue), &ekey);
  GNUNET_GE_ASSERT (NULL,
                    GNUNET_OK ==
                    GNUNET_EC_file_block_encode ((DBlock *) & blk[1],
                                                 ntohl (blk->size) -
                                                 sizeof
                                                 (GNUNET_DatastoreValue),
                                                 &ekey, &eblk));
  if ((0 == memcmp (&ekey, key, sizeof (GNUNET_HashCode)))
      && (value->size == blk->size)
      && (0 ==
          memcmp (&value[1], &eblk[1],
                  ntohl (value->size) - sizeof (GNUNET_DatastoreValue))))
    {
      cls->found = GNUNET_YES;
      GNUNET_semaphore_up (cls->sem);
      ret = GNUNET_SYSERR;
    }
  else
    {
      GNUNET_GE_BREAK (NULL, 0);
      printf ("Received unexpected result.\n");
      ret = GNUNET_OK;
    }
  GNUNET_free (eblk);
  GNUNET_free (blk);
  return ret;
}

static int
trySearch (int i)
{
  GNUNET_CronTime now;
  GNUNET_HashCode query;
  TSC closure;
  GNUNET_DatastoreValue *dv;
  DBlock *db;
  struct GNUNET_FS_SearchContext *ctx;

  ctx = GNUNET_FS_create_search_context (NULL, cfg, lock);
  dv = makeBlock (i);
  db = (DBlock *) & dv[1];
  GNUNET_EC_file_block_get_query (db,
                                  ntohl (dv->size) -
                                  sizeof (GNUNET_DatastoreValue), &query);
  GNUNET_free (dv);
  closure.found = GNUNET_NO;
  closure.i = i;
  closure.sem = GNUNET_semaphore_create (0);
  now = GNUNET_get_time ();
  GNUNET_FS_start_search (ctx,
                          NULL,
                          GNUNET_ECRS_BLOCKTYPE_DATA,
                          1, &query, 0, &searchResultCB, &closure);
  GNUNET_cron_add_job (cron, &abortSem, 30 * GNUNET_CRON_SECONDS, 0,
                       closure.sem);
  GNUNET_semaphore_down (closure.sem, GNUNET_YES);
  GNUNET_cron_suspend_jobs (cron, GNUNET_NO);
  GNUNET_cron_del_job (cron, &abortSem, 0, closure.sem);
  GNUNET_cron_resume_jobs (cron, GNUNET_NO);
  GNUNET_semaphore_destroy (closure.sem);
  GNUNET_FS_destroy_search_context (ctx);
  return closure.found;
}

#define START_DAEMON 1

int
main (int argc, char *argv[])
{
#if START_DAEMON
  pid_t daemon;
#endif
  int ok;
  struct GNUNET_FS_SearchContext *ctx = NULL;
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_DatastoreValue *block = NULL;
  GNUNET_DatastoreValue *eblock;
  GNUNET_HashCode hc;
  GNUNET_HashCode query;
  int i;
  char *tmpName;
  int fd;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  now = GNUNET_get_time ();
  cron = GNUNET_cron_create (NULL);
#if START_DAEMON
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon > 0);
#endif
  ok = GNUNET_YES;
  GNUNET_cron_start (cron);
  lock = GNUNET_mutex_create (GNUNET_NO);
#if START_DAEMON
  GNUNET_GE_ASSERT (NULL,
                    GNUNET_OK == GNUNET_wait_for_daemon_running (NULL, cfg,
                                                                 60 *
                                                                 GNUNET_CRON_SECONDS));
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
#endif
  sock = GNUNET_client_connection_create (NULL, cfg);
  CHECK (sock != NULL);

  /* ACTUAL TEST CODE */
  for (i = 1; i < 32; i++)
    {
      fprintf (stderr, ".");
      block = makeBlock (i);
      GNUNET_EC_file_block_get_query ((DBlock *) & block[1],
                                      ntohl (block->size) -
                                      sizeof (GNUNET_DatastoreValue), &query);
      CHECK (GNUNET_OK ==
             GNUNET_EC_file_block_encode ((DBlock *) & block[1],
                                          ntohl (block->size) -
                                          sizeof (GNUNET_DatastoreValue),
                                          &query, &eblock));
      eblock->expirationTime = block->expirationTime;
      eblock->prio = block->prio;
      CHECK (GNUNET_OK == GNUNET_FS_insert (sock, eblock));
      CHECK (GNUNET_OK == trySearch (i));
      CHECK (GNUNET_SYSERR != GNUNET_FS_delete (sock, eblock));
      GNUNET_free (eblock);
      GNUNET_hash (&((DBlock *) & block[1])[1],
                   ntohl (block->size) - sizeof (GNUNET_DatastoreValue) -
                   sizeof (DBlock), &hc);
      /* indexing without symlink */
      CHECK (GNUNET_OK == GNUNET_FS_index (sock, &hc, block, 0));
      CHECK (GNUNET_OK == trySearch (i));
      CHECK (GNUNET_OK ==
             GNUNET_FS_unindex (sock, GNUNET_MAX_BUFFER_SIZE, &hc));
      /* indexing with symlink */
      tmpName = GNUNET_strdup ("/tmp/symlinkTestXXXXXX");
      CHECK (-1 != (fd = mkstemp (tmpName)));
      CHECK (-1 != WRITE (fd,
                          &((DBlock *) & block[1])[1],
                          ntohl (block->size) -
                          sizeof (GNUNET_DatastoreValue) - sizeof (DBlock)));
      CLOSE (fd);
      CHECK (GNUNET_FS_prepare_to_index (sock, &hc, tmpName) == GNUNET_YES);
      CHECK (GNUNET_OK == GNUNET_FS_index (sock, &hc, block, 0));
      CHECK (GNUNET_OK == trySearch (i));
      CHECK (GNUNET_OK ==
             GNUNET_FS_unindex (sock, GNUNET_MAX_BUFFER_SIZE, &hc));
      UNLINK (tmpName);
      GNUNET_free (tmpName);
      GNUNET_free (block);
      block = NULL;
    }
  fprintf (stderr, "\n");
  for (i = 32; i < GNUNET_MAX_BUFFER_SIZE; i *= 2)
    {
      fprintf (stderr, ".");
      block = makeBlock (i);
      GNUNET_EC_file_block_get_query ((DBlock *) & block[1],
                                      ntohl (block->size) -
                                      sizeof (GNUNET_DatastoreValue), &query);
      CHECK (GNUNET_OK ==
             GNUNET_EC_file_block_encode ((DBlock *) & block[1],
                                          ntohl (block->size) -
                                          sizeof (GNUNET_DatastoreValue),
                                          &query, &eblock));
      eblock->expirationTime = block->expirationTime;
      eblock->prio = block->prio;
      CHECK (GNUNET_OK == GNUNET_FS_insert (sock, eblock));
      CHECK (GNUNET_OK == trySearch (i));
      CHECK (1 == GNUNET_FS_delete (sock, eblock));
      GNUNET_free (eblock);
      GNUNET_hash (&((DBlock *) & block[1])[1],
                   ntohl (block->size) - sizeof (GNUNET_DatastoreValue) -
                   sizeof (DBlock), &hc);
      CHECK (GNUNET_OK == GNUNET_FS_index (sock, &hc, block, 0));
      CHECK (GNUNET_OK == trySearch (i));
      CHECK (GNUNET_OK ==
             GNUNET_FS_unindex (sock, GNUNET_MAX_BUFFER_SIZE, &hc));
      GNUNET_free (block);
      block = NULL;
    }
  fprintf (stderr, "\n");

  /* multiple search results test */
  GNUNET_create_random_hash (&hc);
  block = makeKBlock (40, &hc, &query);
  CHECK (GNUNET_OK == GNUNET_FS_insert (sock, block));
  GNUNET_free (block);
  block = makeKBlock (60, &hc, &query);
  CHECK (GNUNET_OK == GNUNET_FS_insert (sock, block));
  GNUNET_free (block);
  block = NULL;
  i = 2;
  mainThread = GNUNET_thread_get_self ();
  ctx = GNUNET_FS_create_search_context (NULL, cfg, lock);
  GNUNET_FS_start_search (ctx,
                          NULL,
                          GNUNET_ECRS_BLOCKTYPE_ANY,
                          1, &query, 0, &countCallback, &i);
  if (i > 0)
    GNUNET_thread_sleep (1 * GNUNET_CRON_SECONDS);
  GNUNET_thread_release_self (mainThread);
  GNUNET_FS_destroy_search_context (ctx);
  CHECK (i <= 0);

  /* END OF TEST CODE */

FAILURE:
  fprintf (stderr, "\n");
  if (sock != NULL)
    GNUNET_client_connection_destroy (sock);
  GNUNET_mutex_destroy (lock);
  GNUNET_cron_stop (cron);
  GNUNET_cron_destroy (cron);
  GNUNET_free_non_null (block);
#if START_DAEMON
  GNUNET_GE_ASSERT (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
#endif
  GNUNET_GC_free (cfg);
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of fslibtest.c */

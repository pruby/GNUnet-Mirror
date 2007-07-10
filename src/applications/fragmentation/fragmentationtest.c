/*
     This file is part of GNUnet
     (C) 2004 Christian Grothoff (and other contributing authors)

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
 * @file server/testfragmentation.c
 * @brief test for fragmentation.c
 * @author Christian Grothoff
 */

/**
 * Testcase for defragmentation code.
 * We have testcases for:
 * - 2 fragments, aligned, [0,16),[16,32)
 * - n (50) fragments, [i*16,(i+1)*16)
 * - n (50) fragments, [0,i*16) + [50*16,51*16)
 * - n (100) fragments, inserted in interleaved order (holes in sequence)
 * - holes in sequence
 * - other overlaps
 * - timeouts
 * - multiple entries in hash-list
 * - id collisions in hash-list
 */

/* -- to speed up the testcases -- */
#define DEFRAGMENTATION_TIMEOUT (1 * cronSECONDS)

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_cron.h"

#include "fragmentation.c"

static PeerIdentity mySender;
static char *myMsg;
static unsigned short myMsgLen;

/* static buffers to avoid lots of malloc/free */
static char masterBuffer[65536];
static char resultBuffer[65536];

static void
handleHelper (const PeerIdentity * sender,
              const char *msg,
              const unsigned int len, int wasEncrypted, TSession * ts)
{
  GE_ASSERT (NULL, 0 == memcmp (sender, &mySender, sizeof (PeerIdentity)));
  myMsg = resultBuffer;
  memcpy (resultBuffer, msg, len);
  myMsgLen = len;
}

/**
 * Wait long enough to force all fragments to timeout.
 */
static void
makeTimeout ()
{
  PTHREAD_SLEEP (DEFRAGMENTATION_TIMEOUT * 2);
  defragmentationPurgeCron (NULL);
}

/**
 * Create a fragment. The data-portion will be filled
 * with a sequence of numbers from start+id to start+len-1+id.
 *
 * @param pep pointer to the ethernet frame/buffer
 * @param ip pointer to the ip-header
 * @param start starting-offset
 * @param length of the data portion
 * @param id the identity of the fragment
 */
static MESSAGE_HEADER *
makeFragment (unsigned short start,
              unsigned short size, unsigned short tot, int id)
{
  P2P_fragmentation_MESSAGE *frag;
  int i;

  frag = (P2P_fragmentation_MESSAGE *) masterBuffer;
  frag->id = htonl (id);
  frag->off = htons (start);
  frag->len = htons (tot);
  frag->header.size = htons (sizeof (P2P_fragmentation_MESSAGE) + size);

  for (i = 0; i < size; i++)
    ((char *) &frag[1])[i] = (char) i + id + start;
  return &frag->header;
}

/**
 * Check that the packet received is what we expected to
 * get.
 * @param id the expected id
 * @param len the expected length
 */
static void
checkPacket (int id, unsigned int len)
{
  int i;

  GE_ASSERT (NULL, myMsg != NULL);
  GE_ASSERT (NULL, myMsgLen == len);
  for (i = 0; i < len; i++)
    GE_ASSERT (NULL, myMsg[i] == (char) (i + id));
  myMsgLen = 0;
  myMsg = NULL;
}


/* **************** actual testcases ***************** */

static void
testSimpleFragment ()
{
  MESSAGE_HEADER *pep;

  pep = makeFragment (0, 16, 32, 42);
  processFragment (&mySender, pep);
  GE_ASSERT (NULL, myMsg == NULL);
  pep = makeFragment (16, 16, 32, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 32);
}

static void
testSimpleFragmentTimeout ()
{
  MESSAGE_HEADER *pep;

  pep = makeFragment (0, 16, 32, 42);
  processFragment (&mySender, pep);
  GE_ASSERT (NULL, myMsg == NULL);
  makeTimeout ();
  pep = makeFragment (16, 16, 32, 42);
  processFragment (&mySender, pep);
  GE_ASSERT (NULL, myMsg == NULL);
  pep = makeFragment (0, 16, 32, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 32);
}

static void
testSimpleFragmentReverse ()
{
  MESSAGE_HEADER *pep;

  pep = makeFragment (16, 16, 32, 42);
  processFragment (&mySender, pep);
  GE_ASSERT (NULL, myMsg == NULL);
  pep = makeFragment (0, 16, 32, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 32);
}

static void
testManyFragments ()
{
  MESSAGE_HEADER *pep;
  int i;

  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (i * 16, 16, 51 * 16, 42);
      processFragment (&mySender, pep);
      GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (50 * 16, 16, 51 * 16, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 51 * 16);
}

static void
testManyFragmentsMegaLarge ()
{
  MESSAGE_HEADER *pep;
  int i;

  for (i = 0; i < 4000; i++)
    {
      pep = makeFragment (i * 16, 16, 4001 * 16, 42);
      processFragment (&mySender, pep);
      GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (4000 * 16, 16, 4001 * 16, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 4001 * 16);
}

static void
testLastFragmentEarly ()
{
  MESSAGE_HEADER *pep;
  int i;

  for (i = 0; i < 5; i++)
    {
      pep = makeFragment (i * 16, 8, 6 * 16 + 8, 42);
      processFragment (&mySender, pep);
      GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (5 * 16, 24, 6 * 16 + 8, 42);
  processFragment (&mySender, pep);
  for (i = 0; i < 5; i++)
    {
      pep = makeFragment (i * 16 + 8, 8, 6 * 16 + 8, 42);
      processFragment (&mySender, pep);
    }
  checkPacket (42, 6 * 16 + 8);
}

static void
testManyInterleavedFragments ()
{
  MESSAGE_HEADER *pep;
  int i;

  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (i * 16, 8, 51 * 16 + 8, 42);
      processFragment (&mySender, pep);
      GE_ASSERT (NULL, myMsg == NULL);
    }
  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (i * 16 + 8, 8, 51 * 16 + 8, 42);
      processFragment (&mySender, pep);
      GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (50 * 16, 24, 51 * 16 + 8, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 51 * 16 + 8);
}

static void
testManyInterleavedOverlappingFragments ()
{
  MESSAGE_HEADER *pep;
  int i;

  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (i * 32, 16, 51 * 32, 42);
      processFragment (&mySender, pep);
      GE_ASSERT (NULL, myMsg == NULL);
    }
  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (i * 32 + 8, 24, 51 * 32, 42);
      processFragment (&mySender, pep);
      GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (50 * 32, 32, 51 * 32, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 51 * 32);
}

static void
testManyOverlappingFragments ()
{
  MESSAGE_HEADER *pep;
  int i;

  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (0, i * 16 + 16, 51 * 16, 42);
      processFragment (&mySender, pep);
      GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (50 * 16, 16, 51 * 16, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 51 * 16);
}

static void
testManyOverlappingFragmentsTimeout ()
{
  MESSAGE_HEADER *pep;
  int i;

  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (0, i * 16 + 16, 51 * 16 + 8, 42);
      processFragment (&mySender, pep);
      GE_ASSERT (NULL, myMsg == NULL);
    }
  makeTimeout ();
  pep = makeFragment (50 * 16, 24, 51 * 16 + 8, 42);
  processFragment (&mySender, pep);
  GE_ASSERT (NULL, myMsg == NULL);
  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (0, i * 16 + 16, 51 * 16 + 8, 42);
      processFragment (&mySender, pep);
    }
  checkPacket (42, 51 * 16 + 8);
}

static void
testManyFragmentsMultiId ()
{
  MESSAGE_HEADER *pep;
  int i;
  int id;

  for (i = 0; i < 50; i++)
    {
      for (id = 0; id < DEFRAG_BUCKET_COUNT; id++)
        {
          pep = makeFragment (i * 16, 16, 51 * 16, id + 5);
          mySender.hashPubKey.bits[0] = id;
          processFragment (&mySender, pep);
          GE_ASSERT (NULL, myMsg == NULL);
        }
    }
  for (id = 0; id < DEFRAG_BUCKET_COUNT; id++)
    {
      pep = makeFragment (50 * 16, 16, 51 * 16, id + 5);
      mySender.hashPubKey.bits[0] = id;
      processFragment (&mySender, pep);
      checkPacket (id + 5, 51 * 16);
    }
}

static void
testManyFragmentsMultiIdCollisions ()
{
  MESSAGE_HEADER *pep;
  int i;
  int id;

  for (i = 0; i < 5; i++)
    {
      for (id = 0; id < DEFRAG_BUCKET_COUNT * 4; id++)
        {
          pep = makeFragment (i * 16, 16, 6 * 16, id + 5);
          mySender.hashPubKey.bits[0] = id;
          processFragment (&mySender, pep);
          GE_ASSERT (NULL, myMsg == NULL);
        }
    }
  for (id = 0; id < DEFRAG_BUCKET_COUNT * 4; id++)
    {
      pep = makeFragment (5 * 16, 16, 6 * 16, id + 5);
      mySender.hashPubKey.bits[0] = id;
      processFragment (&mySender, pep);
      checkPacket (id + 5, 6 * 16);
    }
}

/* ************* driver ****************** */

static int
registerp2pHandler (const unsigned short type, MessagePartHandler callback)
{
  return OK;
}

static int
unregisterp2pHandler (const unsigned short type, MessagePartHandler callback)
{
  return OK;
}


static void *
requestService (const char *name)
{
  return NULL;
}

int
main (int argc, char *argv[])
{
  CoreAPIForApplication capi;

  memset (&capi, 0, sizeof (CoreAPIForApplication));
  capi.cron = cron_create (NULL);
  capi.injectMessage = &handleHelper;
  capi.requestService = &requestService;
  capi.registerHandler = &registerp2pHandler;
  capi.unregisterHandler = &unregisterp2pHandler;
  provide_module_fragmentation (&capi);

  fprintf (stderr, ".");
  testSimpleFragment ();
  fprintf (stderr, ".");
  testSimpleFragmentTimeout ();
  fprintf (stderr, ".");
  testSimpleFragmentReverse ();
  fprintf (stderr, ".");
  testManyFragments ();
  fprintf (stderr, ".");
  testManyFragmentsMegaLarge ();
  fprintf (stderr, ".");
  testManyFragmentsMultiId ();
  fprintf (stderr, ".");

  testManyInterleavedFragments ();
  fprintf (stderr, ".");
  testManyInterleavedOverlappingFragments ();
  fprintf (stderr, ".");
  testManyOverlappingFragments ();
  fprintf (stderr, ".");
  testManyOverlappingFragmentsTimeout ();
  fprintf (stderr, ".");
  testLastFragmentEarly ();
  fprintf (stderr, ".");
  testManyFragmentsMultiIdCollisions ();
  fprintf (stderr, ".");
  release_module_fragmentation ();
  fprintf (stderr, "\n");
  cron_destroy (capi.cron);
  return 0;                     /* testcase passed */
}

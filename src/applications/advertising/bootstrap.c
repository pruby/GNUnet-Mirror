/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file advertising/bootstrap.c
 * @brief Cron-jobs that trigger bootstrapping
 *  if we have too few connections.
 *
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_bootstrap_service.h"
#include "gnunet_state_service.h"

#define DEBUG_BOOTSTRAP GNUNET_NO

#define hello_HELPER_TABLE_START_SIZE 64

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Bootstrap_ServiceAPI *bootstrap;

static GNUNET_State_ServiceAPI *state;

static struct GNUNET_ThreadHandle *pt;

typedef struct
{
  GNUNET_MessageHello **hellos;
  unsigned int hellosCount;
  unsigned int hellosLen;
  int do_shutdown;
} HelloListClosure;

static HelloListClosure hlc;

static int
testTerminate (void *cls)
{
  HelloListClosure *c = cls;
  return !c->do_shutdown;
}

static void
processhellos (HelloListClosure * hcq)
{
  int rndidx;
  int i;
  GNUNET_MessageHello *msg;

  if (NULL == hcq)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return;
    }
  while ((!hcq->do_shutdown) && (hcq->hellosCount > 0))
    {
      /* select hellos in random order */
      rndidx =
        GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, hcq->hellosCount);
#if DEBUG_BOOTSTRAP
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "%s chose hello %d of %d\n",
                     __FUNCTION__, rndidx, hcq->hellosCount);
#endif
      msg = (GNUNET_MessageHello *) hcq->hellos[rndidx];
      hcq->hellos[rndidx] = hcq->hellos[hcq->hellosCount - 1];
      GNUNET_array_grow (hcq->hellos, hcq->hellosCount, hcq->hellosCount - 1);

      coreAPI->loopback_send (NULL,
                              (const char *) msg,
                              ntohs (msg->header.size), GNUNET_NO, NULL);
      GNUNET_free (msg);
      if ((hcq->hellosCount > 0) && (!hlc.do_shutdown))
        {
          /* wait a bit */
          unsigned int load;
          int nload;
          load = GNUNET_cpu_get_load (coreAPI->ectx, coreAPI->cfg);
          if (load == (unsigned int) -1)
            load = 50;
          nload =
            GNUNET_network_monitor_get_load (coreAPI->load_monitor,
                                             GNUNET_ND_UPLOAD);
          if (nload > load)
            load = nload;
          nload = GNUNET_network_monitor_get_load (coreAPI->load_monitor,
                                                   GNUNET_ND_DOWNLOAD);
          if (nload > load)
            load = nload;
          if (load > 100)
            load = 100;

          GNUNET_thread_sleep (50 +
                               GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                                  (load + 1) * (load + 1)));
        }
    }
  for (i = 0; i < hcq->hellosCount; i++)
    GNUNET_free (hcq->hellos[i]);
  GNUNET_array_grow (hcq->hellos, hcq->hellosCount, 0);
}

static void
downloadHostlistCallback (const GNUNET_MessageHello * hello, void *c)
{
  HelloListClosure *cls = c;
  if (cls->hellosCount >= cls->hellosLen)
    {
      GNUNET_array_grow (cls->hellos,
                         cls->hellosLen,
                         cls->hellosLen + hello_HELPER_TABLE_START_SIZE);
    }
  cls->hellos[cls->hellosCount++] =
    GNUNET_malloc (ntohs (hello->header.size));
  memcpy (cls->hellos[cls->hellosCount - 1], hello,
          ntohs (hello->header.size));
}

#define BOOTSTRAP_INFO "bootstrap-info"

static int
needBootstrap ()
{
  static GNUNET_CronTime lastTest;
  static GNUNET_CronTime delta;
  GNUNET_CronTime now;
  char *data;

  now = GNUNET_get_time ();
  if (coreAPI->p2p_connections_iterate (NULL, NULL) >=
      GNUNET_MIN_CONNECTION_TARGET)
    {
      /* still change delta and lastTest; even
         if the peer _briefly_ drops below MCT
         connections, we don't want it to immediately
         go for the hostlist... */
      delta = 5 * GNUNET_CRON_MINUTES;
      lastTest = now;
      return GNUNET_NO;
    }
  if (lastTest == 0)
    {
      /* first run in this process */
      if (-1 != state->read (coreAPI->ectx, BOOTSTRAP_INFO, (void **) &data))
        {
          /* but not first on this machine */
          lastTest = now;
          delta = 2 * GNUNET_CRON_MINUTES;      /* wait 2 minutes */
          GNUNET_free (data);
        }
      else
        {
          /* first on this machine, too! */
          state->write (coreAPI->ectx, BOOTSTRAP_INFO, 1, "X");
          delta = 60 * GNUNET_CRON_SECONDS;
        }
    }
  if (now - lastTest > delta)
    {
      lastTest = now;
      delta *= 2;               /* exponential back-off */
      /* Maybe it should ALSO be based on how many peers
         we know (identity).
         Sure, in the end it goes to the topology, so
         probably that API should be extended here... */
      return GNUNET_YES;
    }
  /* wait a bit longer */
  return GNUNET_NO;
}

static void *
processThread (void *unused)
{
  hlc.hellos = NULL;
  while (GNUNET_NO == hlc.do_shutdown)
    {
      while (GNUNET_NO == hlc.do_shutdown)
        {
          GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
          if (needBootstrap ())
            break;
        }
      if (GNUNET_YES == hlc.do_shutdown)
        break;
#if DEBUG_BOOTSTRAP
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Starting bootstrap.\n");
#endif
      hlc.hellosLen = 0;
      hlc.hellosCount = 0;
      bootstrap->bootstrap (&downloadHostlistCallback,
                            &hlc, &testTerminate, &hlc);
      GNUNET_array_grow (hlc.hellos, hlc.hellosLen, hlc.hellosCount);
      processhellos (&hlc);
    }
  return NULL;
}

/**
 * Start using the bootstrap service to obtain
 * advertisements if needed.
 */
void
startBootstrap (GNUNET_CoreAPIForPlugins * capi)
{
  coreAPI = capi;
  state = capi->service_request ("state");
  GNUNET_GE_ASSERT (capi->ectx, state != NULL);
  bootstrap = capi->service_request ("bootstrap");
  GNUNET_GE_ASSERT (capi->ectx, bootstrap != NULL);
  hlc.do_shutdown = GNUNET_NO;
  pt = GNUNET_thread_create (&processThread, NULL, 64 * 1024);
  GNUNET_GE_ASSERT (capi->ectx, pt != NULL);
}

/**
 * Stop advertising.
 */
void
stopBootstrap ()
{
  void *unused;

  hlc.do_shutdown = GNUNET_YES;
  GNUNET_thread_stop_sleep (pt);
  GNUNET_thread_join (pt, &unused);
  pt = NULL;
  coreAPI->service_release (bootstrap);
  bootstrap = NULL;
  coreAPI->service_release (state);
  state = NULL;
  coreAPI = NULL;
}

/* end of bootstrap.c */

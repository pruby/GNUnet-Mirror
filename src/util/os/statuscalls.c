/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/os/statuscalls.c
 * @brief calls to determine current network load
 * @author Tzvetan Horozov
 * @author Christian Grothoff
 * @author Igor Wronsky
 * @author Heikki Lindholm
 *
 * Status calls implementation for load management.
 */

#include "platform.h"
#include "gnunet_util_os.h"
#include "gnunet_util_error.h"
#include "gnunet_util_string.h"
#include "gnunet_util_threads.h"

#if SOLARIS
#if HAVE_KSTAT_H
#include <kstat.h>
#endif
#if HAVE_SYS_SYSINFO_H
#include <sys/sysinfo.h>
#endif
#if HAVE_KVM_H
#include <kvm.h>
#endif
#endif
#if SOMEBSD
#if HAVE_KVM_H
#include <kvm.h>
#endif
#endif
#if OSX
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_mib.h>
#endif
#define DEBUG_STATUSCALLS GNUNET_NO

/**
 * where to read network interface information from
 * under Linux
 */
#define PROC_NET_DEV "/proc/net/dev"

typedef struct
{

  char *name;

  unsigned long long last_in;

  unsigned long long last_out;
} NetworkStats;

typedef struct
{
  unsigned long long overload;

  unsigned long long lastSum;

  GNUNET_CronTime lastCall;

  int lastValue;

  /**
   * Can we compute statistics (because we have a previous
   * value)?  GNUNET_YES or GNUNET_NO.
   */
  int have_last;

  /**
   * Maximum bandwidth as per config.
   */
  unsigned long long max;

} DirectionInfo;

typedef struct GNUNET_LoadMonitor
{

  /**
   * Traffic counter for only gnunetd traffic.
   */
  NetworkStats globalTrafficBetweenProc;

  /**
   * tracking
   */
  NetworkStats *ifcs;

  /**
   * how many interfaces do we have?
   */
  unsigned int ifcsSize;

  /**
   * How to measure traffic (GNUNET_YES == only gnunetd,
   * GNUNET_NO == try to include all apps)
   */
  int useBasicMethod;

#ifdef LINUX
  FILE *proc_net_dev;
#endif

  /**
   * Lock.
   */
  struct GNUNET_Mutex *statusMutex;

  struct GNUNET_GE_Context *ectx;

  struct GNUNET_GC_Configuration *cfg;

  DirectionInfo upload_info;

  DirectionInfo download_info;

  GNUNET_CronTime last_ifc_update;

} LoadMonitor;

void
GNUNET_network_monitor_notify_transmission (struct GNUNET_LoadMonitor
                                            *monitor,
                                            GNUNET_NETWORK_DIRECTION dir,
                                            unsigned long long delta)
{
  GNUNET_mutex_lock (monitor->statusMutex);
  if (dir == GNUNET_ND_DOWNLOAD)
    monitor->globalTrafficBetweenProc.last_in += delta;
  else
    monitor->globalTrafficBetweenProc.last_out += delta;
  GNUNET_mutex_unlock (monitor->statusMutex);
}

#define MAX_PROC_LINE 5000

static void
updateInterfaceTraffic (struct GNUNET_LoadMonitor *monitor)
{
#ifdef LINUX
  unsigned long long rxnew;
  unsigned long long txnew;
  int i;
  char line[MAX_PROC_LINE];
  NetworkStats *ifc;
  char *data;

  if (monitor->proc_net_dev != NULL)
    {
      rewind (monitor->proc_net_dev);
      /* Parse the line matching the interface ('eth0') */
      while (!feof (monitor->proc_net_dev))
        {
          if (NULL == fgets (line, MAX_PROC_LINE, monitor->proc_net_dev))
            break;
          for (i = 0; i < monitor->ifcsSize; i++)
            {
              ifc = &monitor->ifcs[i];
              if (NULL != strstr (line, ifc->name))
                {
                  data = strchr (line, ':');
                  if (data == NULL)
                    continue;
                  data++;
                  if (2 != SSCANF (data,
                                   "%llu %*s %*s %*s %*s %*s %*s %*s %llu",
                                   &rxnew, &txnew))
                    {
                      GNUNET_GE_LOG (monitor->ectx,
                                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                     GNUNET_GE_BULK,
                                     _
                                     ("Failed to parse interface data from `%s'.\n"),
                                     PROC_NET_DEV);
                      continue;
                    }
                  ifc->last_in = rxnew;
                  ifc->last_out = txnew;
                  monitor->globalTrafficBetweenProc.last_in = 0;
                  monitor->globalTrafficBetweenProc.last_out = 0;
                  break;
                }
            }
        }
    }
#elif OSX
  int name[6];
  size_t len;
  int rows;
  int j;
  int i;
  NetworkStats *ifc;

  name[0] = CTL_NET;
  name[1] = PF_LINK;
  name[2] = NETLINK_GENERIC;
  name[3] = IFMIB_SYSTEM;
  name[4] = IFMIB_IFCOUNT;

  len = sizeof (rows);

  if (sysctl (name, 5, &rows, &len, (void *) 0, 0) == 0)
    {
      for (j = 1; j <= rows; j++)
        {
          struct ifmibdata ifmd;

          name[0] = CTL_NET;
          name[1] = PF_LINK;
          name[2] = NETLINK_GENERIC;
          name[3] = IFMIB_IFDATA;
          name[4] = j;
          name[5] = IFDATA_GENERAL;

          len = sizeof (ifmd);
          if (sysctl (name, 6, &ifmd, &len, (void *) 0, 0) != 0)
            {
              if (errno == ENOENT)
                continue;
              else
                {
                  GNUNET_GE_LOG_STRERROR (monitor->ectx,
                                          GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                          GNUNET_GE_BULK, "sysctl");
                  break;
                }
            }
          for (i = 0; i < monitor->ifcsSize; i++)
            {
              ifc = &monitor->ifcs[i];
              if (strcmp (ifc->name, ifmd.ifmd_name) == 0)
                {
                  ifc->last_in = ifmd.ifmd_data.ifi_ibytes;
                  ifc->last_out = ifmd.ifmd_data.ifi_obytes;
                  monitor->globalTrafficBetweenProc.last_in = 0;
                  monitor->globalTrafficBetweenProc.last_out = 0;
                  break;
                }
            }
        }
    }
  else
    {
      GNUNET_GE_LOG_STRERROR (monitor->ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_BULK, "sysctl");
    }
#elif MINGW
  NetworkStats *ifc;
  PMIB_IFTABLE pTable;
  DWORD dwIfIdx;
  unsigned long long l;
  BYTE bPhysAddr[MAXLEN_PHYSADDR];
  int iLine = 0;
  FILE *command;
  unsigned long long rxnew;
  unsigned long long txnew;
  int i;
  char line[MAX_PROC_LINE];

  /* Win 98 and NT SP 4 */
  if (GNGetIfEntry)
    {
      EnumNICs (&pTable, NULL);
      for (i = 0; i < monitor->ifcsSize; i++)
        {
          ifc = &monitor->ifcs[i];
          for (dwIfIdx = 0; dwIfIdx < pTable->dwNumEntries; dwIfIdx++)
            {
              l = _atoi64 (ifc->name);
              memset (bPhysAddr, 0, MAXLEN_PHYSADDR);
              memcpy (bPhysAddr,
                      pTable->table[dwIfIdx].bPhysAddr,
                      pTable->table[dwIfIdx].dwPhysAddrLen);
              if (0 == memcmp (bPhysAddr, &l, sizeof (unsigned long long)))
                {
                  ifc->last_in = pTable->table[dwIfIdx].dwInOctets;
                  ifc->last_out = pTable->table[dwIfIdx].dwOutOctets;
                  monitor->globalTrafficBetweenProc.last_in = 0;
                  monitor->globalTrafficBetweenProc.last_out = 0;
                  break;
                }
            }
        }
      GlobalFree (pTable);
    }
  else
    {                           /* Win 95 */
      if ((command = popen ("netstat -e", "rt")) == NULL)
        {
          GNUNET_GE_LOG_STRERROR_FILE (monitor->ectx,
                                       GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                       GNUNET_GE_BULK, "popen", "netstat -e");
          return;
        }
      ifc = &monitor->ifcs[0];
      while (!feof (command))
        {
          if (NULL == fgets (line, MAX_PROC_LINE, command))
            break;
          /* PORT-ME: any way to do this per-ifc? */
          if (iLine == 1)
            {
              if (2 == sscanf ("%*s%i%i", &rxnew, &txnew))
                {
                  ifc->last_in = rxnew;
                  ifc->last_out = txnew;
                  monitor->globalTrafficBetweenProc.last_in = 0;
                  monitor->globalTrafficBetweenProc.last_out = 0;
                  break;
                }
              else
                {
                  GNUNET_GE_LOG (monitor->ectx,
                                 GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                 GNUNET_GE_BULK,
                                 _
                                 ("Failed to parse interface data from `%s'.\n"),
                                 PROC_NET_DEV);
                }
            }
          iLine++;
        }
      pclose (command);
    }
#else
  /* PORT-ME! */
#endif
}

/**
 * Re-read the configuration for statuscalls.
 */
static int
resetStatusCalls (void *cls,
                  struct GNUNET_GC_Configuration *cfg,
                  struct GNUNET_GE_Context *ectx, const char *sect,
                  const char *op)
{
  struct GNUNET_LoadMonitor *monitor = cls;
  char *interfaces;
  int i;
  int numInterfaces;
  int basic;

  if (0 != strcmp (sect, "LOAD"))
    return 0;                   /* fast path */
  basic = GNUNET_GC_get_configuration_value_yesno (cfg,
                                                   "LOAD", "BASICLIMITING",
                                                   GNUNET_YES);
  if (basic == GNUNET_SYSERR)
    return GNUNET_SYSERR;
  if (-1 == GNUNET_GC_get_configuration_value_string (cfg,
                                                      "LOAD",
                                                      "INTERFACES",
                                                      GNUNET_DEFAULT_INTERFACE,
                                                      &interfaces))
    return GNUNET_SYSERR;
  if (interfaces == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _
                     ("No network interfaces defined in configuration section `%s' under `%s'!\n"),
                     "LOAD", "INTERFACES");
      return GNUNET_SYSERR;
    }
  if (strlen (interfaces) == 0)
    {
      GNUNET_free (interfaces);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _
                     ("No network interfaces defined in configuration section `%s' under `%s'!\n"),
                     "LOAD", "INTERFACES");
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_lock (monitor->statusMutex);
  for (i = 0; i < monitor->ifcsSize; i++)
    GNUNET_free (monitor->ifcs[i].name);
  numInterfaces = 1;
  for (i = strlen (interfaces) - 1; i >= 0; i--)
    if (interfaces[i] == ',')
      numInterfaces++;
  GNUNET_array_grow (monitor->ifcs, monitor->ifcsSize, numInterfaces);
  for (i = strlen (interfaces) - 1; i >= 0; i--)
    {
      if (interfaces[i] == ',')
        {
          monitor->ifcs[--numInterfaces].name =
            GNUNET_strdup (&interfaces[i + 1]);
          numInterfaces++;
          interfaces[i] = '\0';
        }
    }
  monitor->ifcs[--numInterfaces].name = GNUNET_strdup (interfaces);
  GNUNET_GE_ASSERT (ectx, numInterfaces == 0);
  for (i = 0; i < monitor->ifcsSize; i++)
    {
      monitor->ifcs[i].last_in = 0;
      monitor->ifcs[i].last_out = 0;
    }
  monitor->upload_info.have_last = GNUNET_NO;
  monitor->upload_info.lastCall = 0;
  monitor->upload_info.overload = 0;
  monitor->download_info.have_last = GNUNET_NO;
  monitor->download_info.lastCall = 0;
  monitor->download_info.overload = 0;
  GNUNET_free (interfaces);
  monitor->useBasicMethod = basic;
  GNUNET_GC_get_configuration_value_number (cfg,
                                            "LOAD",
                                            "MAXNETDOWNBPSTOTAL",
                                            0,
                                            (unsigned long long) -1,
                                            50000,
                                            &monitor->download_info.max);
  GNUNET_GC_get_configuration_value_number (cfg, "LOAD", "MAXNETUPBPSTOTAL",
                                            0, (unsigned long long) -1, 50000,
                                            &monitor->upload_info.max);
  monitor->last_ifc_update = GNUNET_get_time ();
  updateInterfaceTraffic (monitor);
  GNUNET_mutex_unlock (monitor->statusMutex);
  return 0;
}

/**
 * Get the total amoung of bandwidth this load monitor allows
 * in bytes per second
 *
 * @return the maximum bandwidth in bytes per second, -1 for no limit
 */
unsigned long long
GNUNET_network_monitor_get_limit (struct GNUNET_LoadMonitor *monitor,
                                  GNUNET_NETWORK_DIRECTION dir)
{
  if (monitor == NULL)
    return -1;
  if (dir == GNUNET_ND_UPLOAD)
    return monitor->upload_info.max;
  else if (dir == GNUNET_ND_DOWNLOAD)
    return monitor->download_info.max;
  return -1;
}

#define INCREMENTAL_INTERVAL (60 * GNUNET_CRON_SECONDS)

/**
 * Get the load of the network relative to what is allowed.
 * @return the network load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int
GNUNET_network_monitor_get_load (struct GNUNET_LoadMonitor *monitor,
                                 GNUNET_NETWORK_DIRECTION dir)
{
  DirectionInfo *di;
  GNUNET_CronTime now;
  unsigned long long maxExpect;
  unsigned long long currentLoadSum;
  unsigned long long currentTotal;
  int i;
  int ret;
  int weight;

  if (monitor == NULL)
    return 0;                   /* no limits */
  if (dir == GNUNET_ND_UPLOAD)
    di = &monitor->upload_info;
  else
    di = &monitor->download_info;

  GNUNET_mutex_lock (monitor->statusMutex);
  now = GNUNET_get_time ();
  if ((monitor->useBasicMethod == GNUNET_NO) &&
      (now - monitor->last_ifc_update > 10 * GNUNET_CRON_SECONDS))
    {
      monitor->last_ifc_update = now;
      updateInterfaceTraffic (monitor);
    }
  if (dir == GNUNET_ND_UPLOAD)
    {
      currentTotal = monitor->globalTrafficBetweenProc.last_out;
      for (i = 0; i < monitor->ifcsSize; i++)
        currentTotal += monitor->ifcs[i].last_out;
    }
  else
    {
      currentTotal = monitor->globalTrafficBetweenProc.last_in;
      for (i = 0; i < monitor->ifcsSize; i++)
        currentTotal += monitor->ifcs[i].last_in;
    }
  if ((di->lastSum > currentTotal) ||
      (di->have_last == GNUNET_NO) || (now < di->lastCall))
    {
      /* integer overflow or first datapoint; since we cannot tell where
         / by how much the overflow happened, all we can do is ignore
         this datapoint.  So we return -1 -- AND reset lastSum / lastCall. */
      di->lastSum = currentTotal;
      di->lastCall = now;
      di->have_last = GNUNET_YES;
      GNUNET_mutex_unlock (monitor->statusMutex);
      return -1;
    }
  if (di->max == 0)
    {
      GNUNET_mutex_unlock (monitor->statusMutex);
      return -1;
    }

  maxExpect = (now - di->lastCall) * di->max / GNUNET_CRON_SECONDS;
  if (now - di->lastCall < INCREMENTAL_INTERVAL)
    {
      /* return weighted average between last return value and
         load in the last interval */
      weight = (now - di->lastCall) * 100 / INCREMENTAL_INTERVAL;       /* how close are we to lastCall? */
      if (maxExpect == 0)
        ret = di->lastValue;
      else
        ret =
          di->lastValue * (100 - weight) / 100 + weight * (currentTotal -
                                                           di->lastSum +
                                                           di->overload) /
          maxExpect;
      GNUNET_mutex_unlock (monitor->statusMutex);
      return ret;
    }

  currentLoadSum = currentTotal - di->lastSum + di->overload;
  di->lastSum = currentTotal;
  di->lastCall = now;
  if (currentLoadSum < maxExpect)
    di->overload = 0;
  else
    di->overload = currentLoadSum - maxExpect;
  ret = currentLoadSum * 100 / maxExpect;
  di->lastValue = ret;
  GNUNET_mutex_unlock (monitor->statusMutex);
  return ret;
}

struct GNUNET_LoadMonitor *
GNUNET_network_monitor_create (struct GNUNET_GE_Context *ectx,
                               struct GNUNET_GC_Configuration *cfg)
{
  struct GNUNET_LoadMonitor *monitor;

  monitor = GNUNET_malloc (sizeof (struct GNUNET_LoadMonitor));
  memset (monitor, 0, sizeof (struct GNUNET_LoadMonitor));
  monitor->ectx = ectx;
  monitor->cfg = cfg;
#ifdef LINUX
  monitor->proc_net_dev = fopen (PROC_NET_DEV, "r");
  if (NULL == monitor->proc_net_dev)
    GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                 GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                 GNUNET_GE_USER | GNUNET_GE_BULK, "fopen",
                                 PROC_NET_DEV);
#endif
  monitor->statusMutex = GNUNET_mutex_create (GNUNET_NO);
  if (-1 ==
      GNUNET_GC_attach_change_listener (cfg, &resetStatusCalls, monitor))
    {
      GNUNET_network_monitor_destroy (monitor);
      return NULL;
    }
  return monitor;
}

void
GNUNET_network_monitor_destroy (struct GNUNET_LoadMonitor *monitor)
{
  int i;

  GNUNET_GC_detach_change_listener (monitor->cfg, &resetStatusCalls, monitor);
#ifdef LINUX
  if (monitor->proc_net_dev != NULL)
    fclose (monitor->proc_net_dev);
#endif
  for (i = 0; i < monitor->ifcsSize; i++)
    GNUNET_free (monitor->ifcs[i].name);
  GNUNET_array_grow (monitor->ifcs, monitor->ifcsSize, 0);
  GNUNET_mutex_destroy (monitor->statusMutex);
  GNUNET_free (monitor);
}

/* end of statuscalls.c */

/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003 Christian Grothoff (and other contributing authors)

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
 * @file util/statuscalls.c
 * @brief calls to determine current network and CPU load
 * @author Tzvetan Horozov
 * @author Christian Grothoff
 * @author Igor Wronsky
 *
 * Status calls implementation for load management.
 *
 * Todo:
 * - determining load between calls to /proc might be made
 *   interface specific
 * - port to other platforms
 */

#include "platform.h"
#include "gnunet_util.h"

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

#define DEBUG_STATUSCALLS NO

/* where to read network interface information from
   under Linux */
#define PROC_NET_DEV "/proc/net/dev"

typedef struct {
  unsigned long long last_in;
  unsigned long long last_out;
} NetworkStats;

static char ** interfacePtrs = NULL; /* Pointer to the name of each interface, has numInterfaces entries */
static int numInterfaces = 0; /* how many interfaces do we have? */

/* configuration */
static int maxNetDownBPS;
static int maxNetUpBPS;
static int maxCPULoad; 		   /* in percent of 1 CPU */
static double lastNetResultUp = -1;   /* the max upstream load we saw last time */
static double lastNetResultDown = -1; /* the max dnstream load we saw last time */
static cron_t lastnettimeUp =  0;  /* when did we check last time? */
static cron_t lastnettimeDown =  0;  /* when did we check last time? */
static int useBasicMethod = YES;   /* how to measure traffic */

/* tracking */
static NetworkStats * last_net_results; /* has numInterfaces entries */

/* for async configuration update! */
static Mutex statusMutex;

static NetworkStats globalTrafficBetweenProc;

static int initialized_ = NO;

/**
 * Increment the number of bytes sent.  Transports should use this
 * so that statuscalls module can measure gnunet traffic usage between
 * calls to /proc.
 *
 * Note: the caller doesn't know what interface it is attached to,
 * so this type of bandwidth limitation is always global (for all
 * network interfaces).
 */
void incrementBytesSent(unsigned long long delta) {
  if (initialized_ == NO)
    return;
  MUTEX_LOCK(&statusMutex);
  globalTrafficBetweenProc.last_out += delta;
  MUTEX_UNLOCK(&statusMutex);
}

void incrementBytesReceived(unsigned long long delta) {
  if (initialized_ == NO)
    return;
  MUTEX_LOCK(&statusMutex);
  globalTrafficBetweenProc.last_in += delta;
  MUTEX_UNLOCK(&statusMutex);
}


static void cronLoadUpdate(void * unused) {
  getCPULoad();
  getNetworkLoadUp();
  getNetworkLoadDown();
}

/**
 * Re-read the configuration for statuscalls.
 */
static void resetStatusCalls() {
  char * interfaces;
  char * ifcs;
  int start;

  MUTEX_LOCK(&statusMutex);
  interfaces
    = getConfigurationString("LOAD",
			     "INTERFACES");
  ifcs = interfaces;
  /* fail if config-file is incomplete */
  if (interfaces == NULL) {
    LOG(LOG_ERROR,
	_("No network interfaces defined in configuration section '%s' under '%s'!\n"),
	"LOAD",
	"INTERFACES");
    numInterfaces = 0;
    MUTEX_UNLOCK(&statusMutex);
    return;
  }

  /* The string containing the interfaces is formatted in the following way:
   * each comma is replaced by '\0' and the pointers to the beginning of every
   * interface are stored
   */
  numInterfaces = 0;
  start = YES;
  while (1) {
    if (*interfaces == '\0') {
      if (start == NO)
	numInterfaces++;
      break;
    }
    if ( ((*interfaces>='a') && (*interfaces<='z')) ||
	 ((*interfaces>='A') && (*interfaces<='Z')) ||
	 ((*interfaces>='0') && (*interfaces<='9')) ) {
      start = NO;
    } else {
      if (*interfaces != ',')
	errexit(_("Interfaces string (%s) in configuration section '%s' under '%s' is malformed.\n"),
		ifcs,
		"LOAD",
		"INTERFACES");
      if (start == NO) {
	start = YES;
	numInterfaces++;
      }
    }
    interfaces++;
  }
  if (numInterfaces <= 0) {
    LOG(LOG_ERROR,
	_("No network interfaces specified in the configuration file in section '%s' under '%s'.\n"),
	"LOAD",
	"INTERFACES");
    MUTEX_UNLOCK(&statusMutex);
    return;
  }

  if (interfacePtrs != NULL) {
    FREE(interfacePtrs[0]);
    FREE(interfacePtrs);
  }
  interfacePtrs = MALLOC(sizeof(char*) * numInterfaces);
  last_net_results = MALLOC(sizeof(NetworkStats) * numInterfaces);
  memset(last_net_results, 0,
	 sizeof(NetworkStats) * numInterfaces);

  /* 2nd pass, this time remember the positions */
  interfaces = ifcs;
  numInterfaces = 0;
  start = YES;
  while (1) {
    if (*interfaces=='\0') {
      if (start == NO)
	numInterfaces++;
      break;
    }
    if ( ((*interfaces>='a') && (*interfaces<='z')) ||
	 ((*interfaces>='A') && (*interfaces<='Z')) ||
	 ((*interfaces>='0') && (*interfaces<='9')) ) {
      if (start == YES) {
	start = NO;
	interfacePtrs[numInterfaces] = interfaces;	
      }
    } else {
      if (start == NO) {
	start = YES;
	*interfaces = '\0';	
	numInterfaces++;
      }
    }
    interfaces++;
  }

  useBasicMethod
    = testConfigurationString("LOAD",
 			      "BASICLIMITING",
			      "YES");
  maxNetDownBPS
    = getConfigurationInt("LOAD",
			  "MAXNETDOWNBPSTOTAL");
  if (maxNetDownBPS == 0)
    maxNetDownBPS = 50000;
  maxNetUpBPS
    = getConfigurationInt("LOAD",
			  "MAXNETUPBPSTOTAL");
  if (maxNetUpBPS == 0)
    maxNetUpBPS = 50000;
  maxCPULoad
    = getConfigurationInt("LOAD",
			  "MAXCPULOAD");
  if (maxCPULoad == 0)
    maxCPULoad = 100;
  MUTEX_UNLOCK(&statusMutex);
}

#ifdef LINUX
static FILE * proc_stat = NULL;
#endif

/**
 * The basic usage meter considers only gnunetd traffic.
 */
static int networkUsageBasicUp() {
  cron_t now, elapsedTime;
  double upUsage;
  double etc;

  MUTEX_LOCK(&statusMutex);
  /* If called less than 1 seconds ago, calc average
     between avg. traffic of last second and the additional
     gained traffic.  If more than 1 second between calls,
     set the avg bytes/sec as the usage of last second. */
  cronTime(&now);
  elapsedTime = now - lastnettimeUp;
  etc = (double) elapsedTime / (double) cronSECONDS;
  if (elapsedTime < cronSECONDS) {
    upUsage = ( ( lastNetResultUp +
		  ((double)globalTrafficBetweenProc.last_out * etc) )
		/ (1.0 + etc) );
  } else {
    upUsage = (double)globalTrafficBetweenProc.last_out / etc;
    lastNetResultUp = upUsage;
    globalTrafficBetweenProc.last_out = 0;
    lastnettimeUp = now;
  }
  MUTEX_UNLOCK(&statusMutex);
  return (int)(100.0 * ((double)upUsage / (double)maxNetUpBPS));
}

/**
 * The basic usage meter considers only gnunetd traffic.
 */
static int networkUsageBasicDown() {
  cron_t now, elapsedTime;
  double downUsage;
  double etc;

  MUTEX_LOCK(&statusMutex);
  /* If called less than 1 seconds ago, calc average
     between avg. traffic of last second and the additional
     gained traffic. If more than 1 second between calls,
     set the avg bytes/sec as the usage of last second. */
  cronTime(&now);
  elapsedTime = now - lastnettimeDown;
  etc = (double) elapsedTime / (double) cronSECONDS;
  if (elapsedTime < cronSECONDS) {
    downUsage = ( ( lastNetResultDown +
		    ((double)globalTrafficBetweenProc.last_in * etc) )
		  / (1.0 + etc) );
  } else {
    downUsage = (double)globalTrafficBetweenProc.last_in / etc;
    lastNetResultDown = downUsage;
    globalTrafficBetweenProc.last_in = 0;
    lastnettimeDown = now;
  }
  MUTEX_UNLOCK(&statusMutex);
  return (int)(100.0 * (double)downUsage / (double)maxNetDownBPS);
}

/**
 * The advanced usage meter takes into account all network traffic.
 * This might be problematic on systems where the same interface
 * can have different capabilities for different types of traffic
 * (like support for very fast local traffic but capable of
 * handling only small-scale inet traffic).
 */
static int networkUsageAdvancedDown() {
#define MAX_PROC_LINE 5000
  char line[MAX_PROC_LINE];
  unsigned long long rxnew, txnew;
  unsigned long long rxdiff;
  int i=0;
  int ifnum;
  cron_t now, elapsedtime;

#ifdef LINUX
  FILE * proc_net_dev;
  char * data;
#else
  FILE * command;
#endif

  MUTEX_LOCK(&statusMutex);

  /* first, make sure maxNetDownBPS is not 0, we don't want
     to divide by 0, really. */
  if (maxNetDownBPS == 0) {
    lastNetResultDown = -1;
    MUTEX_UNLOCK(&statusMutex);
    return -1;
  }

  /* If we checked /proc less than 2 seconds ago, don't do
     it again, but add internal gnunet traffic increments */
  cronTime(&now);
  elapsedtime = now - lastnettimeDown;
  if (elapsedtime == 0) {
    MUTEX_UNLOCK(&statusMutex);
    return (int) lastNetResultDown;
  }
  if (elapsedtime < 2 * cronSECONDS) {
    /* Only take additional gnunetd traffic into account, don't try to
       measure other *system* traffic more frequently than every 2s */
    double gnunetBPS;
    double gnunetLOAD;
    int ret;

    gnunetBPS
      = (cronMILLIS/cronSECONDS) * globalTrafficBetweenProc.last_in / elapsedtime;
    gnunetLOAD
      = 100 * gnunetBPS / maxNetDownBPS;
    /* weigh last global measurement and gnunetd load,
       with 100% global measurement at first and 50/50 mix
       just before we take the next measurement */
    ret = ( (2 * cronSECONDS * lastNetResultDown + elapsedtime * gnunetLOAD) /
	    (2 * cronSECONDS + elapsedtime));
    MUTEX_UNLOCK(&statusMutex);
    return ret;
  }

  globalTrafficBetweenProc.last_in = 0;
  lastnettimeDown = now;

  /* ok, full program... */
  rxdiff = 0;

#ifdef LINUX
  proc_net_dev = fopen(PROC_NET_DEV, "r");
  /* Try to open the file*/
  if (NULL == proc_net_dev) {
    LOG_FILE_STRERROR(LOG_ERROR, "fopen", PROC_NET_DEV);
    MUTEX_UNLOCK(&statusMutex);
    lastNetResultDown = -1;
    return -1;
  }
  ifnum = 0;
  /* Parse the line matching the interface ('eth0') */
  while ( (!feof(proc_net_dev)) &&
	  ( ifnum < numInterfaces) ) {
    fgets(line,
	  MAX_PROC_LINE,
	  proc_net_dev);

    for (i=0;i<numInterfaces;i++) {
      if (NULL != strstr(line, interfacePtrs[i]) ) {
	data = (char*)strchr(line, ':');
	data++;	
	if (sscanf(data,
		   "%llu %*s %*s %*s %*s %*s %*s %*s %llu",
		  &rxnew, &txnew) != 2) {
	  fclose(proc_net_dev);	
	  errexit(_("Failed to parse interface data from '%s' at %s:%d.\n"),
		  PROC_NET_DEV, __FILE__, __LINE__);
	}
	if ( (signed long long)(rxnew - last_net_results[ifnum].last_in) > 0) {
	  /* ignore the result if it is currently overflowing */
	  rxdiff += rxnew - last_net_results[ifnum].last_in;
	}
	last_net_results[ifnum].last_in = rxnew;
	ifnum++;
	break;
      }
    }
  }
  fclose(proc_net_dev);
#elif MINGW
  /* Win 98 and NT SP 4 */
  if (GNGetIfEntry)
  {
    for (ifnum=0; ifnum < numInterfaces; ifnum++)
    {
      PMIB_IFTABLE pTable;
      DWORD dwIfIdx;
      int found = 0;

      EnumNICs(&pTable, NULL);

      for(dwIfIdx=0; dwIfIdx < pTable->dwNumEntries; dwIfIdx++) {
        unsigned long long l;
        BYTE bPhysAddr[MAXLEN_PHYSADDR];

        l = _atoi64(interfacePtrs[i]);

        memset(bPhysAddr, 0, MAXLEN_PHYSADDR);
        memcpy(bPhysAddr,
          pTable->table[dwIfIdx].bPhysAddr,
          pTable->table[dwIfIdx].dwPhysAddrLen);

        if (memcmp(bPhysAddr, &l, sizeof(l)) == 0) {
          found = 1;
          break;
        }
      }

      if (found)
        rxnew = pTable->table[dwIfIdx].dwInOctets;
      else
        rxnew = last_net_results[ifnum].last_in;

      rxdiff += rxnew - last_net_results[ifnum].last_in;
      last_net_results[ifnum].last_in = rxnew;

      GlobalFree(pTable);
    }
  }
  else
  {
    /* Win 95 */
    int iLine = 0;

    if ( ( command = popen("netstat -e", "rt") ) == NULL )
    {
      LOG_FILE_STRERROR(LOG_ERROR, "popen", "netstat -e");
      lastNetResultDown = -1;
      MUTEX_UNLOCK(&statusMutex);
      return -1;
    }
    while (!feof(command))
    {
      fgets(line, MAX_PROC_LINE, command);
      if (iLine == 1)
      {
        char szDummy[100];
        sscanf("%s%i%i", szDummy, &rxnew, &txnew);
	      rxdiff += rxnew - last_net_results[0].last_in;	
	      last_net_results[0].last_in = rxnew;
      }
      iLine++;
    }
    pclose(command);
  }
#else
  if (1) {
    MUTEX_UNLOCK(&statusMutex);
    return 0;
  }
  if ( ( command = popen("netstat -n -f inet -i", "r") ) == NULL ) {
    LOG_FILE_STRERROR(LOG_ERROR, "popen", "netstat -n -f inet -i");
    lastNetResultDown = -1;
    MUTEX_UNLOCK(&statusMutex);
    return -1;
  }
  ifnum = 0;
  while ( (!feof(command)) &&
	  (ifnum < numInterfaces ) ) {
    fgets(line,
	  MAX_PROC_LINE,
	  command);
    for (i=0; i < numInterfaces; i++) {
      if ( NULL != strstr(line, interfacePtrs[i]) ) {
	if(sscanf(line, "%*s %*s %*s %*s %llu %*s %llu %*s %*s",
		  &rxnew, &txnew) != 2 ) {
	  pclose(command);
	  errexit(_("Failed to parse interface data '%s' output at %s:%d.\n"),
		  "netstat -n -f inet -i",
		  __FILE__, __LINE__);
	}
	if ( (signed long long)(rxnew - last_net_results[ifnum].last_in) > 0) {
	  /* ignore the result if it is currently overflowing */
	  rxdiff += rxnew - last_net_results[ifnum].last_in;
	}
	last_net_results[ifnum].last_in = rxnew;
	ifnum++;
	break;
      } /* if match */
    }  /* for all interfaces, find match */
  } /* while: for all lines in proc */
  pclose(command);
#endif

  lastNetResultDown
    = (100 * rxdiff * cronSECONDS) / (elapsedtime * maxNetDownBPS);
	
  MUTEX_UNLOCK(&statusMutex);
  return (int) lastNetResultDown;
}


/**
 * The advanced usage meter takes into account all network traffic.
 * This might be problematic on systems where the same interface
 * can have different capabilities for different types of traffic
 * (like support for very fast local traffic but capable of
 * handling only small-scale inet traffic).
 */
static int networkUsageAdvancedUp() {
#define MAX_PROC_LINE 5000
  char line[MAX_PROC_LINE];
  unsigned long long rxnew, txnew;
  unsigned long long txdiff;
  int i=0;
  int ifnum;
  cron_t now, elapsedtime;

#ifdef LINUX
  FILE * proc_net_dev;
  char * data;
#else
  FILE * command;
#endif

  MUTEX_LOCK(&statusMutex);

  /* first, make sure maxNetUpBPS is not 0, we don't want
     to divide by 0, really. */
  if (maxNetUpBPS == 0) {
    lastNetResultUp = -1;
    MUTEX_UNLOCK(&statusMutex);
    return -1;
  }

  /* If we checked /proc less than 2 seconds ago, don't do
     it again, but add internal gnunet traffic increments */
  cronTime(&now);
  elapsedtime = now - lastnettimeUp;
  if (elapsedtime == 0) {
    MUTEX_UNLOCK(&statusMutex);
    return (int) lastNetResultUp;
  }

  if (elapsedtime < 2 * cronSECONDS) {
    /* Only take additional gnunetd traffic into account, don't try to
       measure other *system* traffic more frequently than every 2s */
    double gnunetBPS;
    double gnunetLOAD;
    int ret;

    gnunetBPS
      = (cronMILLIS/cronSECONDS) * globalTrafficBetweenProc.last_out / elapsedtime;
    gnunetLOAD
      = 100 * gnunetBPS / maxNetUpBPS;
    /* weigh last global measurement and gnunetd load,
       with 100% global measurement at first and 50/50 mix
       just before we take the next measurement */
    ret = ( (2 * cronSECONDS * lastNetResultUp + elapsedtime * gnunetLOAD) /
	    (2 * cronSECONDS + elapsedtime));
    MUTEX_UNLOCK(&statusMutex);
    return ret;
  }

  globalTrafficBetweenProc.last_out = 0;
  lastnettimeUp = now;

  /* ok, full program... */
  txdiff = 0;

#ifdef LINUX
  proc_net_dev = fopen(PROC_NET_DEV, "r");
  /* Try to open the file*/
  if (NULL == proc_net_dev) {
    LOG_FILE_STRERROR(LOG_ERROR, "fopen", PROC_NET_DEV);
    MUTEX_UNLOCK(&statusMutex);
    lastNetResultUp = -1;
    return -1;
  }
  ifnum = 0;
  /* Parse the line matching the interface ('eth0') */
  while ( (!feof(proc_net_dev)) &&
	  ( ifnum < numInterfaces) ) {
    fgets(line,
	  MAX_PROC_LINE,
	  proc_net_dev);

    for (i=0;i<numInterfaces;i++) {
      if (NULL != strstr(line, interfacePtrs[i]) ) {
	data = (char*)strchr(line, ':');
	data++;	
	if (sscanf(data,
		   "%llu %*s %*s %*s %*s %*s %*s %*s %llu",
		  &rxnew, &txnew) != 2) {
	  fclose(proc_net_dev);
	  errexit(_("Failed to parse interface data from '%s' at %s:%d.\n"),
		  PROC_NET_DEV, __FILE__, __LINE__);
	} 	
	if ( (signed long long)(txnew - last_net_results[ifnum].last_out) > 0) {
	  /* ignore the result if it is currently overflowing */
	  txdiff += txnew - last_net_results[ifnum].last_out;
	}
	last_net_results[ifnum].last_out = txnew;
	ifnum++;
	break;
      }
    }
  }
  fclose(proc_net_dev);
#elif MINGW
  /* Win 98 and NT SP 4 */
  if (GNGetIfEntry)
  {
    for (ifnum=0; ifnum < numInterfaces; ifnum++)
    {
      PMIB_IFTABLE pTable;
      DWORD dwIfIdx;
      int found = 0;

      EnumNICs(&pTable, NULL);

      for(dwIfIdx=0; dwIfIdx < pTable->dwNumEntries; dwIfIdx++) {
        unsigned long long l;
        BYTE bPhysAddr[MAXLEN_PHYSADDR];

        l = _atoi64(interfacePtrs[i]);

        memset(bPhysAddr, 0, MAXLEN_PHYSADDR);
        memcpy(bPhysAddr,
          pTable->table[dwIfIdx].bPhysAddr,
          pTable->table[dwIfIdx].dwPhysAddrLen);

        if (memcmp(bPhysAddr, &l, sizeof(l)) == 0) {
          found = 1;
          break;
        }
      }

      if (found)
        txnew = pTable->table[dwIfIdx].dwOutOctets;
      else
        txnew = last_net_results[ifnum].last_out;

      txdiff += txnew - last_net_results[ifnum].last_out;
      last_net_results[ifnum].last_out = txnew;

      GlobalFree(pTable);
    }
  }
  else
  {
    /* Win 95 */
    int iLine = 0;

    if ((command = popen("netstat -e", "rt")) == NULL)
    {
      LOG_FILE_STRERROR(LOG_ERROR, "popen", "netstat -e");
      lastNetResultUp = -1;
      MUTEX_UNLOCK(&statusMutex);
      return -1;
    }
    while (!feof(command))
    {
      fgets(line, MAX_PROC_LINE, command);
      if (iLine == 1)
      {
        char szDummy[100];
        sscanf("%s%i%i", szDummy, &rxnew, &txnew);
	      txdiff += txnew - last_net_results[0].last_out;	
	      last_net_results[0].last_out = txnew;
      }
      iLine++;
    }
    pclose(command);
  }
#else
  if (1) {
    MUTEX_UNLOCK(&statusMutex);
    return 0;
  }
  if ( ( command = popen("netstat -n -f inet -i", "r") ) == NULL ) {
    LOG_FILE_STRERROR(LOG_ERROR, "popen", "netstat -n -f inet -i");
    lastNetResultUp = -1;
    MUTEX_UNLOCK(&statusMutex);
    return -1;
  }
  ifnum = 0;
  while ( (!feof(command)) &&
	  (ifnum < numInterfaces ) ) {
    fgets(line,
	  MAX_PROC_LINE,
	  command);
    for (i=0; i < numInterfaces; i++) {
      if ( NULL != strstr(line, interfacePtrs[i]) ) {
	if(sscanf(line, "%*s %*s %*s %*s %llu %*s %llu %*s %*s",
		  &rxnew, &txnew) != 2 ) {
	  pclose(command);
	  errexit(" reading interface data using netstat\n");
	}
	if ( (signed long long)(txnew - last_net_results[ifnum].last_out) > 0) {
	  /* ignore the result if it is currently overflowing */
	  txdiff += txnew - last_net_results[ifnum].last_out;
	}
	last_net_results[ifnum].last_out = txnew;
	ifnum++;
	break;
      } /* if match */
    }  /* for all interfaces, find match */
  } /* while: for all lines in proc */
  pclose(command);
#endif

  lastNetResultUp
    = (100 * txdiff * cronSECONDS) / (elapsedtime * maxNetUpBPS);
	
  MUTEX_UNLOCK(&statusMutex);
  return (int) lastNetResultUp;
}

/**
 * The following routine returns the percentage of available used
 * bandwidth.  Example: If 81 is returned this means that 81% of the
 * network bandwidth of the host is consumed.  The method
 * initStatusCalls() should be called before this routine is invoked.
 * If there is an error the method returns -1.
 */
int networkUsageUp() {
  if (initialized_ == NO)
    return -1;
  if (useBasicMethod == YES)
    return networkUsageBasicUp();
  else
    return networkUsageAdvancedUp();
}

/**
 * The following routine returns the percentage of available used
 * bandwidth.  Example: If 81 is returned this means that 81% of the
 * network bandwidth of the host is consumed.  The method
 * initStatusCalls() should be called before this routine is invoked.
 * If there is an error the method returns -1.
 */
int networkUsageDown() {
  if (initialized_ == NO)
    return -1;
  if (useBasicMethod == YES)
    return networkUsageBasicDown();
  else
    return networkUsageAdvancedDown();
}


/**
 * The following routine returns a number between 0-100 (can be larger than 100
 * if the load is > 1) which indicates the percentage CPU usage.
 *
 * Before its first invocation the method initStatusCalls() must be called.
 * If there is an error the method returns -1
 */
int cpuUsage(){
  static cron_t lastcputime = 0;
  static int lastcpuresult = -1;
  cron_t now, elapsedtime;
#ifdef HAVE_GETLOADAVG
  double loadavg;
#endif

  if (initialized_ == NO)
    return -1;
  MUTEX_LOCK(&statusMutex);
  cronTime(&now);
  elapsedtime = now - lastcputime;
  if ( (elapsedtime < 10 * cronSECONDS) &&
       (lastcpuresult != -1) ) {
    MUTEX_UNLOCK(&statusMutex);
    return lastcpuresult;
  }
  lastcputime = now;

  /* under linux, first try %idle/usage using /proc/stat;
     if that does not work, disable /proc/stat for the future
     by closing the file and use the next-best method. */
#ifdef LINUX
  if (proc_stat != NULL) {
    static int last_cpu_results[4] = { 0, 0, 0, 0 };
    int ret = -1;
    char line[128];
    int user_read, system_read, nice_read, idle_read;
    int user, system, nice, idle;
    int usage_time=0, total_time=1;

    /* Get the first line with the data */
    rewind(proc_stat);
    fflush(proc_stat);
    if (fgets(line, 128, proc_stat)==NULL) {
      LOG_FILE_STRERROR(LOG_ERROR, "fgets", "/proc/stat");
      fclose(proc_stat);
      proc_stat = NULL;
    } else {
      if (sscanf(line, "%*s %i %i %i %i",
		 &user_read, &system_read, &nice_read,
		 &idle_read) != 4) {
	fclose(proc_stat);
	LOG(LOG_ERROR,
	    _("Could not decoding file '%s' at %s:%d.\n"),
	    "/proc/stat",
	    __FILE__, __LINE__);
	proc_stat = NULL; /* don't try again */
      } else {

	/* Store the current usage*/
	user = user_read - last_cpu_results[0];
	system = system_read - last_cpu_results[1];
	nice = nice_read - last_cpu_results[2];
	idle = idle_read - last_cpu_results[3];	
	/* Calculate the % usage */
	if ((user + system + nice + idle) > 0) {
	  usage_time = user + system + nice;
	  total_time = usage_time + idle;
	}
	if (total_time == 0)
	  total_time = 1; /* avoid fpe */
	ret = (100 * usage_time) / total_time;
	/*LOG(LOG_DEBUG,
	    "LOAD: u%d s%d n%d i%d => ret %d\n",
	    user, system, nice, idle, ret);*/
	/* Store the values for the next calculation*/
	last_cpu_results[0] = user_read;
	last_cpu_results[1] = system_read;
	last_cpu_results[2] = nice_read;
	last_cpu_results[3] = idle_read;
	lastcpuresult = ret;
	MUTEX_UNLOCK(&statusMutex);
	return ret;
      }
    }
  }
#endif

  /* try kstat (Solaris only) */
#if SOLARIS
#if HAVE_KSTAT_H
#if HAVE_SYS_SYSINFO_H
  {
    static int kstat_once = 0; /* if open fails, don't keep
				  trying */
    kstat_ctl_t * kc;
    kstat_t * khelper;
    long long idlecount;
    long long totalcount;
    static long long last_idlecount = 0;
    static long long last_totalcount = 0;
    long long deltaidle;
    long long deltatotal;

    if (kstat_once == 0) {
      kc = kstat_open();
      if (kc == NULL)
	LOG_STRERROR(LOG_ERROR, "kstat_open");
    } else {
      kc = NULL;
    }
    if (kc == NULL)
      goto ABORT_KSTAT;

    idlecount = 0;
    totalcount = 0;
    for (khelper = kc->kc_chain;
	 khelper != NULL;
	 khelper = khelper->ks_next) {
      cpu_stat_t stats;

      if (0 != strncmp(khelper->ks_name,
		       "cpu_stat",
		       strlen("cpu_stat")) )
	continue;
      if (khelper->ks_data_size > sizeof(cpu_stat_t))
	continue; /* better save then sorry! */
      if (-1 != kstat_read(kc, khelper, &stats)) {
	idlecount
	  += stats.cpu_sysinfo.cpu[CPU_IDLE];
	totalcount
	  += stats.cpu_sysinfo.cpu[CPU_IDLE] +
	  stats.cpu_sysinfo.cpu[CPU_USER] +
	  stats.cpu_sysinfo.cpu[CPU_KERNEL] +
	  stats.cpu_sysinfo.cpu[CPU_WAIT];
      }
    }
    if (0 != kstat_close(kc))
      LOG_STRERROR(LOG_ERROR, "kstat_close");
    if ( (idlecount == 0) &&
	 (totalcount == 0) )
      goto ABORT_KSTAT; /* no stats found => abort */
    deltaidle = idlecount - last_idlecount;
    deltatotal = totalcount - last_totalcount;
    last_idlecount = idlecount;
    last_totalcount = totalcount;
    if (deltatotal == 0)
      deltatotal = 1; /* avoid fpe */
    /* success! */
    MUTEX_UNLOCK(&statusMutex);
    lastcpuresult = (int) (100 * deltaidle / deltatotal);
    return lastcpuresult;

  ABORT_KSTAT:
    kstat_once = 1; /* failed, don't try again */
  }
#endif
#endif
#endif

  /* maybe try kvm (Solaris, BSD, OSX) here?
     Did Filip say he had some code for this??? */

  /* insert methods better than getloadavg for
     other platforms HERE! */

  /* ok, maybe we have getloadavg on this platform */
#if HAVE_GETLOADAVG
  if (getloadavg(&loadavg, 1) != 1) {
    /* only warn once, if there is a problem with
       getloadavg, we're going to hit it frequently... */
    static int once = 0;
    if (once == 0) {
      once = 1;
      LOG_STRERROR(LOG_ERROR, "getloadavg");
    }
    /* continue with next method -- if we had any... */
  } else {
    /* success with getloadavg */
    lastcpuresult = (int) (100 * loadavg);
    MUTEX_UNLOCK(&statusMutex);
    return lastcpuresult;
  }
#endif

#if MINGW
  /* Win NT? */
  if (GNNtQuerySystemInformation)
  {
    SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION theInfo;
    if (GNNtQuerySystemInformation(SystemProcessorPerformanceInformation,
        &theInfo, sizeof(theInfo), NULL) == NO_ERROR)
    {
      double dKernel, dIdle, dUser, dDiffKernel, dDiffIdle, dDiffUser;
      static double dLastKernel = 0, dLastIdle = 0, dLastUser = 0;

      dKernel = Li2Double(theInfo.KernelTime);
      dIdle = Li2Double(theInfo.IdleTime);
      dUser = Li2Double(theInfo.UserTime);

      if (dLastIdle != 0)
      {
        dDiffKernel = dKernel - dLastKernel;
        dDiffIdle = dIdle - dLastIdle;
        dDiffUser = dUser - dLastUser;

        /* FIXME MINGW: Multi-processor? */
        lastcpuresult = 100.0 - (dDiffIdle / (dDiffKernel + dDiffUser)) * 100.0;
      }
      else
        lastcpuresult = 0; /* don't know (yet) */

      dLastKernel = dKernel;
      dLastIdle = dIdle;
      dLastUser = dUser;

      MUTEX_UNLOCK(&statusMutex);
      return lastcpuresult;
    }
    else
    {
  	  /* only warn once, if there is a problem with
  	     NtQuery..., we're going to hit it frequently... */
  	  static int once = 0;
  	  if (once == 0)
  	  {
  	    once = 1;
  	    LOG(LOG_ERROR,
		_("Cannot query the CPU usage (Windows NT).\n"));
  	  }
    }
  }
  else
  {
    /* Win 9x */
    HKEY hKey;
    DWORD dwDataSize, dwType, dwDummy;

    /* Start query */
    if (RegOpenKeyEx(HKEY_DYN_DATA, "PerfStats\\StartSrv", 0, KEY_ALL_ACCESS,
                     &hKey) != ERROR_SUCCESS)
    {
      /* only warn once */
  	  static int once = 0;
  	  if (once == 0)
  	  {
  	    once = 1;
  	    LOG(LOG_ERROR,
		_("Cannot query the CPU usage (Win 9x)\n"));
  	  }
    }

    RegOpenKeyEx(HKEY_DYN_DATA, "PerfStats\\StartStat", 0, KEY_ALL_ACCESS,
                     &hKey);

    dwDataSize = sizeof(dwDummy);
    RegQueryValueEx(hKey, "KERNEL\\CPUUsage", NULL, &dwType, (LPBYTE) &dwDummy,
                    &dwDataSize);
    RegCloseKey(hKey);

    /* Get CPU usage */
    RegOpenKeyEx(HKEY_DYN_DATA, "PerfStats\\StatData", 0, KEY_ALL_ACCESS,
                 &hKey);
    dwDataSize = sizeof(lastcpuresult);
    RegQueryValueEx(hKey, "KERNEL\\CPUUsage", NULL, &dwType,
                    (LPBYTE) &lastcpuresult, &dwDataSize);
    RegCloseKey(hKey);

    /* Stop query */
    RegOpenKeyEx(HKEY_DYN_DATA, "PerfStats\\StopStat", 0, KEY_ALL_ACCESS,
                 &hKey);
    RegOpenKeyEx(HKEY_DYN_DATA, "PerfStats\\StopSrv", 0, KEY_ALL_ACCESS,
                 &hKey);
    dwDataSize = sizeof(dwDummy);
    RegQueryValueEx(hKey, "KERNEL\\CPUUsage", NULL, &dwType, (LPBYTE)&dwDummy,
                    &dwDataSize);
    RegCloseKey(hKey);

    MUTEX_UNLOCK(&statusMutex);
    return lastcpuresult;
  }
#endif

  /* loadaverage not defined and no platform
     specific alternative defined
     => default: error
  */
  lastcpuresult = -1;
  MUTEX_UNLOCK(&statusMutex);
  return -1;
}

/**
 * Get the load of the network relative to what is allowed.
 * @return the network load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getNetworkLoadUp() {
  static int lastRet = 0;
  static cron_t lastCall = 0;
  int ret;
  cron_t now;

  ret = networkUsageUp();
  if (ret == -1) /* in the case of error, we do NOT go to 100%
		    since that would render GNUnet useless on
		    systems where networkUsageUp is not supported */
    return -1;

  cronTime(&now);
  if (now - lastCall < 250*cronMILLIS) {
    /* use smoothing, but do NOT update lastRet at frequencies higher
       than 250ms; this makes the smoothing (mostly) independent from
       the frequency at which getNetworkLoadUp is called. */
    return (ret + 7 * lastRet)/8;
  }
  lastCall = now;

  ret = (ret + 7 * lastRet)/8;
  lastRet = ret;

  return ret;
}

/**
 * Get the load of the network relative to what is allowed.
 * @return the network load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getNetworkLoadDown() {
  static int lastRet = 0;
  static cron_t lastCall = 0;
  int ret;
  cron_t now;


  if (initialized_ == NO)
    return -1;
  ret = networkUsageDown();
  if (ret == -1) /*  in the case of error, we do NOT go to 100%
		    since that would render GNUnet useless on
		    systems where networkUsageUp is not supported */
    return -1;

  cronTime(&now);
  if (now - lastCall < 250*cronMILLIS) {
    /* use smoothing, but do NOT update lastRet at frequencies higher
       than 250ms; this makes the smoothing (mostly) independent from
       the frequency at which getNetworkLoadDown is called. */
    return (ret + 7 * lastRet)/8;
  }
  lastCall = now;

  ret = (ret + 7 * lastRet)/8;
  lastRet = ret;
  return ret;
}

/**
 * Get the load of the CPU relative to what is allowed.
 * @return the CPU load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getCPULoad() {
  static int lastRet = 0;
  static cron_t lastCall = 0;
  int ret;
  cron_t now;

  if (initialized_ == NO)
    return -1;

  ret = (100 * cpuUsage()) / maxCPULoad;

  cronTime(&now);
  if (now - lastCall < 250*cronMILLIS) {
    /* use smoothing, but do NOT update lastRet at frequencies higher
       than 250ms; this makes the smoothing (mostly) independent from
       the frequency at which getCPULoad is called. */
    return (ret + 7 * lastRet)/8;
  }
  lastCall = now;

  /* for CPU, we don't do the 'fast increase' since CPU is much
     more jitterish to begin with */
  lastRet = (ret + 7 * lastRet)/8;

  return lastRet;
}

/**
 * The following method is called in order to initialize the status calls
 * routines.  After that it is safe to call each of the status calls separately
 * @return OK on success and SYSERR on error (or calls errexit).
 */
void initStatusCalls() {
  initialized_ = YES;
#ifdef LINUX
  proc_stat = fopen("/proc/stat", "r");
  if (NULL == proc_stat)
    LOG_FILE_STRERROR(LOG_ERROR, "fopen", "/proc/stat");
#endif
  MUTEX_CREATE_RECURSIVE(&statusMutex);
  last_net_results = NULL; /* has numInterfaces entries */
  interfacePtrs = NULL;
  last_net_results = NULL;
  globalTrafficBetweenProc.last_in = 0;
  globalTrafficBetweenProc.last_out = 0;
  cronTime(&lastnettimeUp);
  cronTime(&lastnettimeDown);
  registerConfigurationUpdateCallback(&resetStatusCalls);
  resetStatusCalls();
  networkUsageUp();
  networkUsageDown();
  cpuUsage();
  addCronJob(&cronLoadUpdate,
	     10 * cronSECONDS,
	     10 * cronSECONDS,
	     NULL);
}

/**
 * Shutdown the status calls module.
 */
void doneStatusCalls() {
#ifdef LINUX
  if (proc_stat != NULL)
    fclose(proc_stat);
#endif
  unregisterConfigurationUpdateCallback(&resetStatusCalls);
  delCronJob(&cronLoadUpdate,
	     10 * cronSECONDS,
	     NULL);
  if (numInterfaces > 0) {
    FREE(interfacePtrs[0]);
    FREE(interfacePtrs);
  }
  FREENONNULL(last_net_results);
  MUTEX_DESTROY(&statusMutex);
  initialized_ = NO;
}



/* end of statuscalls.c */

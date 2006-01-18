/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2005 Christian Grothoff (and other contributing authors)

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

/**
 * where to read network interface information from
 * under Linux
 */
#define PROC_NET_DEV "/proc/net/dev"

typedef struct {
  char * name;
  unsigned long long last_in;
  unsigned long long last_out;
} NetworkStats;

/**
 * Traffic counter for only gnunetd traffic.
 */
static NetworkStats globalTrafficBetweenProc;

/**
 * tracking
 */
static NetworkStats * ifcs;

/**
 * how many interfaces do we have?
 */
static unsigned int ifcsSize;

/**
 * Current load of the machine, -1 for error
 */
static int currentLoad;

/**
 * Maximum bandwidth (down) as per config.
 */
static int maxNetDownBPS;

/**
 * Maximum bandwidth (up) as per config.
 */
static int maxNetUpBPS;

/**
 * Maximum load as per config.
 */
static int maxCPULoad;

/**
 * How to measure traffic (YES == only gnunetd,
 * NO == try to include all apps)
 */
static int useBasicMethod = YES;

/**
 * Lock.
 */
static Mutex statusMutex;

static int initialized_ = NO;

#ifdef LINUX
static FILE * proc_stat;
static FILE * proc_net_dev;
#endif

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

/**
 * Reset the traffic counters for GNUnet traffic between
 * systemwide readings.
 */
static void resetBetweenProc() {
  globalTrafficBetweenProc.last_in = 0;
  globalTrafficBetweenProc.last_out = 0;
}

#define MAX_PROC_LINE 5000

static void updateInterfaceTraffic() {
#ifdef LINUX
  unsigned long long rxnew;
  unsigned long long txnew;
  char line[MAX_PROC_LINE];
  char * data;
  int i;
  int found;

  MUTEX_LOCK(&statusMutex);
  if (proc_net_dev != NULL) {
    found = 0;
    rewind(proc_net_dev);
    fflush(proc_net_dev);
    /* Parse the line matching the interface ('eth0') */
    while (! feof(proc_net_dev) ) {
      if (NULL == fgets(line,
			MAX_PROC_LINE,
			proc_net_dev))
	break;
      for (i=0;i<ifcsSize;i++) {
	if (NULL != strstr(line, ifcs[i].name) ) {
	  data = strchr(line, ':');
	  if (data == NULL)
	    continue;
	  data++;	
	  if (2 != SSCANF(data,
			  "%llu %*s %*s %*s %*s %*s %*s %*s %llu",
			  &rxnew,
			  &txnew)) {
	    LOG(LOG_ERROR,
		_("Failed to parse interface data from `%s' at %s:%d.\n"),
		PROC_NET_DEV,
		__FILE__,
		__LINE__);
	    continue;
	  }	
	  ifcs[i].last_in  = rxnew;
	  ifcs[i].last_out = txnew;
	  resetBetweenProc();
	  break;
	}
      }
    }
  }
  MUTEX_UNLOCK(&statusMutex);

#elif MINGW
  unsigned long long rxnew;
  unsigned long long txnew;
  int i;
  PMIB_IFTABLE pTable;
  DWORD dwIfIdx;
  unsigned long long l;
  BYTE bPhysAddr[MAXLEN_PHYSADDR];
  int iLine = 0;
  char line[MAX_PROC_LINE];
  FILE * command;

  MUTEX_LOCK(&statusMutex);
  /* Win 98 and NT SP 4 */
  if (GNGetIfEntry) {
    EnumNICs(&pTable, NULL);
    for (i=0;i<ifcsSize;i++) {
      for (dwIfIdx=0; dwIfIdx < pTable->dwNumEntries; dwIfIdx++) {
        l = _atoi64(ifcs[i].name);

        memset(bPhysAddr,
	       0,
	       MAXLEN_PHYSADDR);
        memcpy(bPhysAddr,
	       pTable->table[dwIfIdx].bPhysAddr,
	       pTable->table[dwIfIdx].dwPhysAddrLen);

        if (0 == memcmp(bPhysAddr,
			&l,
			sizeof(unsigned long long))) {
	  ifcs[i].last_in
	    = pTable->table[dwIfIdx].dwInOctets;
	  ifcs[i].last_out
	    = pTable->table[dwIfIdx].dwOutOctets;
	  resetBetweenProc();
          break;
        }
      }
    }
    GlobalFree(pTable);
  } else { /* Win 95 */
    if ( ( command = popen("netstat -e", "rt") ) == NULL ) {
      LOG_FILE_STRERROR(LOG_ERROR,
			"popen",
			"netstat -e");
      MUTEX_UNLOCK(&statusMutex);
      return;
    }
    while (!feof(command)) {
      if (NULL == fgets(line,
			MAX_PROC_LINE,
			command))
	break;
      /* PORT-ME: any way to do this per-ifc? */
      if (iLine == 1) {
        sscanf("%*s%i%i",
	       &rxnew,
	       &txnew);
	ifcs[0].last_in
	  = rxnew;
	ifcs[0].last_out
	  = txnew;
	resetBetweenProc();
	break;
      }
      iLine++;
    }
    pclose(command);
  }
  MUTEX_UNLOCK(&statusMutex);
#else
  /* PORT-ME! */
#endif
}

/**
 * The following routine returns a number between 0-100 (can be larger
 * than 100 if the load is > 1) which indicates the percentage CPU
 * usage.
 *
 * Before its first invocation the method initStatusCalls() must be called.
 * If there is an error the method returns -1
 */
static void updateCpuUsage(){
  if (initialized_ == NO) {
    currentLoad = -1;
    return;
  }
  MUTEX_LOCK(&statusMutex);

#ifdef LINUX
  /* under linux, first try %idle/usage using /proc/stat;
     if that does not work, disable /proc/stat for the future
     by closing the file and use the next-best method. */
  if (proc_stat != NULL) {
    static int last_cpu_results[4] = { 0, 0, 0, 0 };
    char line[128];
    int user_read, system_read, nice_read, idle_read;
    int user, system, nice, idle;
    int usage_time=0, total_time=1;

    /* Get the first line with the data */
    rewind(proc_stat);
    fflush(proc_stat);
    if (NULL == fgets(line, 128, proc_stat)) {
      LOG_FILE_STRERROR(LOG_ERROR,
			"fgets",
			"/proc/stat");
      fclose(proc_stat);
      proc_stat = NULL; /* don't try again */
    } else {
      if (sscanf(line, "%*s %i %i %i %i",
		 &user_read,
		 &system_read,
		 &nice_read,
		 &idle_read) != 4) {
	LOG_FILE_STRERROR(LOG_ERROR,
			  "fgets-sscanf",
			  "/proc/stat");
	fclose(proc_stat);
	proc_stat = NULL; /* don't try again */
      } else {
	/* Store the current usage*/
	user   = user_read - last_cpu_results[0];
	system = system_read - last_cpu_results[1];
	nice   = nice_read - last_cpu_results[2];
	idle   = idle_read - last_cpu_results[3];	
	/* Calculate the % usage */
	if ( (user + system + nice + idle) > 0) {
	  usage_time = user + system + nice;
	  total_time = usage_time + idle;
	}
	if ( (total_time > 0) &&
	     ( (last_cpu_results[0] +
		last_cpu_results[1] +
		last_cpu_results[2] +
		last_cpu_results[3]) > 0) )
	  currentLoad = (100 * usage_time) / total_time;
	else
	  currentLoad = -1;
	/* Store the values for the next calculation*/
	last_cpu_results[0] = user_read;
	last_cpu_results[1] = system_read;
	last_cpu_results[2] = nice_read;
	last_cpu_results[3] = idle_read;
	MUTEX_UNLOCK(&statusMutex);
	return;
      }
    }
  }
#endif

  /* try kstat (Solaris only) */
#if SOLARIS && HAVE_KSTAT_H && HAVE_SYS_SYSINFO_H
  {
    static long long last_idlecount;
    static long long last_totalcount;
    static int kstat_once; /* if open fails, don't keep
			      trying */
    kstat_ctl_t * kc;
    kstat_t * khelper;
    long long idlecount;
    long long totalcount;
    long long deltaidle;
    long long deltatotal;

    if (kstat_once == 1)
      goto ABORT_KSTAT;
    kc = kstat_open();
    if (kc == NULL) {
      LOG_STRERROR(LOG_ERROR, "kstat_open");
      goto ABORT_KSTAT;
    }

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
    if ( (deltatotal > 0) &&
	 (last_totalcount > 0) )
      currentLoad = (int) (100 * deltaidle / deltatotal);
    else
      currentLoad = -1;
    last_idlecount = idlecount;
    last_totalcount = totalcount;
    MUTEX_UNLOCK(&statusMutex);
    return;
  ABORT_KSTAT:
    kstat_once = 1; /* failed, don't try again */
  }
#endif

  /* insert methods better than getloadavg for
     other platforms HERE! */

  /* ok, maybe we have getloadavg on this platform */
#if HAVE_GETLOADAVG
  {
    static int warnOnce = 0;
    double loadavg;
    if (1 != getloadavg(&loadavg, 1)) {
      /* only warn once, if there is a problem with
	 getloadavg, we're going to hit it frequently... */
      if (warnOnce == 0) {
	warnOnce = 1;
	LOG_STRERROR(LOG_ERROR, "getloadavg");
      }
      currentLoad = -1;
    } else {
      /* success with getloadavg */
      currentLoad = (int) (100 * loadavg);
      MUTEX_UNLOCK(&statusMutex);
      return;
    }
  }
#endif

#if MINGW
  /* Win NT? */
  if (GNNtQuerySystemInformation) {
    static double dLastKernel;
    static double dLastIdle;
    static double dLastUser;
    double dKernel;
    double dIdle;
    double dUser;
    double dDiffKernel;
    double dDiffIdle;
    double dDiffUser;
    SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION theInfo;

    if (GNNtQuerySystemInformation(SystemProcessorPerformanceInformation,
				   &theInfo,
				   sizeof(theInfo),
				   NULL) == NO_ERROR) {
      /* PORT-ME MINGW: Multi-processor? */
      dKernel = Li2Double(theInfo.KernelTime);
      dIdle = Li2Double(theInfo.IdleTime);
      dUser = Li2Double(theInfo.UserTime);
      dDiffKernel = dKernel - dLastKernel;
      dDiffIdle = dIdle - dLastIdle;
      dDiffUser = dUser - dLastUser;

      if ( ( (dDiffKernel + dDiffUser) > 0) &&
	   (dLastIdle + dLastKernel + dLastUser > 0) )
        currentLoad = 100.0 - (dDiffIdle / (dDiffKernel + dDiffUser)) * 100.0;
      else
        currentLoad = -1; /* don't know (yet) */

      dLastKernel = dKernel;
      dLastIdle = dIdle;
      dLastUser = dUser;

      MUTEX_UNLOCK(&statusMutex);
      return;
    } else {
      /* only warn once, if there is a problem with
	 NtQuery..., we're going to hit it frequently... */
      static int once;
      if (once == 0) {
	once = 1;
	LOG(LOG_ERROR,
	    _("Cannot query the CPU usage (Windows NT).\n"));
      }
    }
  } else { /* Win 9x */
    HKEY hKey;
    DWORD dwDataSize, dwType, dwDummy;

    /* Start query */
    if (RegOpenKeyEx(HKEY_DYN_DATA,
		     "PerfStats\\StartSrv",
		     0,
		     KEY_ALL_ACCESS,
                     &hKey) != ERROR_SUCCESS) {
      /* only warn once */
      static int once = 0;
      if (once == 0) {
	once = 1;
	LOG(LOG_ERROR,
	    _("Cannot query the CPU usage (Win 9x)\n"));
      }
    }

    RegOpenKeyEx(HKEY_DYN_DATA,
		 "PerfStats\\StartStat",
		 0,
		 KEY_ALL_ACCESS,
		 &hKey);
    dwDataSize = sizeof(dwDummy);
    RegQueryValueEx(hKey,
		    "KERNEL\\CPUUsage",
		    NULL,
		    &dwType,
		    (LPBYTE) &dwDummy,
                    &dwDataSize);
    RegCloseKey(hKey);

    /* Get CPU usage */
    RegOpenKeyEx(HKEY_DYN_DATA,
		 "PerfStats\\StatData",
		 0,
		 KEY_ALL_ACCESS,
                 &hKey);
    dwDataSize = sizeof(currentLoad);
    RegQueryValueEx(hKey,
		    "KERNEL\\CPUUsage",
		    NULL,
		    &dwType,
                    (LPBYTE) &currentLoad,
		    &dwDataSize);
    RegCloseKey(hKey);

    /* Stop query */
    RegOpenKeyEx(HKEY_DYN_DATA,
		 "PerfStats\\StopStat",
		 0,
		 KEY_ALL_ACCESS,
                 &hKey);
    RegOpenKeyEx(HKEY_DYN_DATA,
		 "PerfStats\\StopSrv",
		 0,
		 KEY_ALL_ACCESS,
                 &hKey);
    dwDataSize = sizeof(dwDummy);
    RegQueryValueEx(hKey,
		    "KERNEL\\CPUUsage",
		    NULL,
		    &dwType,
		    (LPBYTE)&dwDummy,
                    &dwDataSize);
    RegCloseKey(hKey);

    MUTEX_UNLOCK(&statusMutex);
    return;
  }
#endif

  /* loadaverage not defined and no platform
     specific alternative defined
     => default: error
  */
  currentLoad = -1;
  MUTEX_UNLOCK(&statusMutex);
}

static void cronLoadUpdate(void * unused) {
  updateCpuUsage();
  if (! useBasicMethod)
    updateInterfaceTraffic();
}

/**
 * Re-read the configuration for statuscalls.
 */
static void resetStatusCalls() {
  char * interfaces;
  int i;
  int numInterfaces;

  MUTEX_LOCK(&statusMutex);
  for (i=0;i<ifcsSize;i++)
    FREE(ifcs[i].name);
  GROW(ifcs,
       ifcsSize,
       0);
  interfaces
    = getConfigurationString("LOAD",
			     "INTERFACES");
  /* fail if config-file is incomplete */
  if ( (interfaces == NULL) ||
       (strlen(interfaces) == 0) ) {
    LOG(LOG_ERROR,
	_("No network interfaces defined in configuration section `%s' under `%s'!\n"),
	"LOAD",
	"INTERFACES");
  } else {
    /* The string containing the interfaces is formatted in the following way:
     * each comma is replaced by '\0' and the pointers to the beginning of every
     * interface are stored
     */
    numInterfaces = 1;
    for (i=strlen(interfaces)-1;i>=0;i--)
      if (interfaces[i] == ',')
	numInterfaces++;
    GROW(ifcs,
	 ifcsSize,
	 numInterfaces);
    for (i=strlen(interfaces)-1;i>=0;i--) {
      if (interfaces[i] == ',') {
	ifcs[--numInterfaces].name = STRDUP(&interfaces[i+1]);
	numInterfaces++;
	interfaces[i] = '\0';
      }
    }
    ifcs[--numInterfaces].name = STRDUP(interfaces);
    GNUNET_ASSERT(numInterfaces == 0);
    for (i=0;i<ifcsSize;i++) {
      ifcs[i].last_in = 0;
      ifcs[i].last_out = 0;
    }
  }
  FREENONNULL(interfaces);
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



/**
 * Get the load of the network relative to what is allowed.
 * @return the network load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getNetworkLoadUp() {
  static unsigned long long overload;
  static unsigned long long lastSum;
  static cron_t lastCall;
  static int lastValue;
  cron_t now;
  unsigned long long maxExpect;
  unsigned long long currentLoadSum;
  int i;
  int ret;

  MUTEX_LOCK(&statusMutex);
  currentLoadSum = globalTrafficBetweenProc.last_out;
  for (i=0;i<ifcsSize;i++)
    currentLoadSum += ifcs[i].last_out;
  cronTime(&now);
  if ( (lastSum > currentLoadSum) ||
       (lastSum == 0) ||
       (now < lastCall) ) {
    /* integer overflow or first datapoint; since we cannot tell where
       / by how much the overflow happened, all we can do is ignore
       this datapoint.  So we return -1 -- AND reset lastSum / lastCall. */
    lastSum = currentLoadSum;
    lastCall = now;
    MUTEX_UNLOCK(&statusMutex);
    return -1;
  }
  if (maxNetUpBPS == 0) {
    MUTEX_UNLOCK(&statusMutex);
    return -1;
  }
  if (now - lastCall < cronSECONDS) {
    /* increase last load proportional to difference in
       data transmitted and in relation to the limit */
    ret = lastValue + 100 * (currentLoadSum - lastSum) / maxNetUpBPS;
    MUTEX_UNLOCK(&statusMutex);
    return ret;
  }
  currentLoadSum -= lastSum;
  lastSum += currentLoadSum;
  currentLoadSum += overload;
  maxExpect = ( (now - lastCall) * maxNetUpBPS ) / cronSECONDS;
  lastCall = now;
  if (currentLoadSum < maxExpect)
    overload = 0;
  else
    overload = currentLoadSum - maxExpect;
  lastValue = currentLoadSum * 100 / maxExpect;
  ret = lastValue;
  MUTEX_UNLOCK(&statusMutex);
  return ret;
}

/**
 * Get the load of the network relative to what is allowed.
 * @return the network load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getNetworkLoadDown() {
  static unsigned long long overload;
  static unsigned long long lastSum;
  static cron_t lastCall;
  static int lastValue;
  cron_t now;
  unsigned long long maxExpect;
  unsigned long long currentLoadSum;
  int i;
  int ret;

  MUTEX_LOCK(&statusMutex);
  currentLoadSum = globalTrafficBetweenProc.last_in;
  for (i=0;i<ifcsSize;i++)
    currentLoadSum += ifcs[i].last_in;
  cronTime(&now);
  if ( (lastSum > currentLoadSum) ||
       (lastSum == 0) ||
       (now < lastCall) ) {
    /* integer overflow or first datapoint; since we cannot tell where
       / by how much the overflow happened, all we can do is ignore
       this datapoint.  So we return -1 -- AND reset lastSum / lastCall. */
    lastSum = currentLoadSum;
    lastCall = now;
    MUTEX_UNLOCK(&statusMutex);
    return -1;
  }
  if (maxNetDownBPS == 0) {
    MUTEX_UNLOCK(&statusMutex);
    return -1;
  }
  if (now - lastCall < cronSECONDS) {
    /* increase last load proportional to difference in
       data transmitted and in relation to the limit */
    ret = lastValue + 100 * (currentLoadSum - lastSum) / maxNetDownBPS;
    MUTEX_UNLOCK(&statusMutex);
    return ret;
  }
  currentLoadSum -= lastSum;
  lastSum += currentLoadSum;
  currentLoadSum += overload;
  maxExpect = ( (now - lastCall) * maxNetDownBPS ) / cronSECONDS;
  lastCall = now;
  if (currentLoadSum < maxExpect)
    overload = 0;
  else
    overload = currentLoadSum - maxExpect;
  lastValue = currentLoadSum * 100 / maxExpect;
  ret = lastValue;
  MUTEX_UNLOCK(&statusMutex);
  return ret;
}

/**
 * Get the load of the CPU relative to what is allowed.
 * @return the CPU load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getCPULoad() {
  static int lastRet = -1;
  static cron_t lastCall;
  int ret;
  cron_t now;

  if (initialized_ == NO) {
    lastRet = -1;
    return -1;
  }
  MUTEX_LOCK(&statusMutex);
  ret = (100 * currentLoad) / maxCPULoad;

  cronTime(&now);
  if ( (lastRet != -1) &&
       (now - lastCall < 250 * cronMILLIS) ) {
    /* use smoothing, but do NOT update lastRet at frequencies higher
       than 250ms; this makes the smoothing (mostly) independent from
       the frequency at which getCPULoad is called. */
    ret = (ret + 7 * lastRet)/8;
    MUTEX_UNLOCK(&statusMutex);
    return ret;
  }

  /* for CPU, we don't do the 'fast increase' since CPU is much
     more jitterish to begin with */
  if (lastRet != -1)
    ret = (ret + 7 * lastRet)/8;
  lastRet = ret;
  lastCall = now;
  MUTEX_UNLOCK(&statusMutex);
  return ret;
}

/**
 * The following method is called in order to initialize the status calls
 * routines.  After that it is safe to call each of the status calls separately
 * @return OK on success and SYSERR on error (or calls errexit).
 */
void initStatusCalls() {
#ifdef LINUX
  proc_stat = fopen("/proc/stat", "r");
  if (NULL == proc_stat)
    LOG_FILE_STRERROR(LOG_ERROR,
		      "fopen",
		      "/proc/stat");
  proc_net_dev = fopen(PROC_NET_DEV, "r");
  if (NULL == proc_net_dev)
    LOG_FILE_STRERROR(LOG_ERROR,
		      "fopen",
		      PROC_NET_DEV);
#endif
  MUTEX_CREATE_RECURSIVE(&statusMutex);
  initialized_ = YES;
  resetBetweenProc();
  registerConfigurationUpdateCallback(&resetStatusCalls);
  resetStatusCalls();
  cronLoadUpdate(NULL);
  addCronJob(&cronLoadUpdate,
	     10 * cronSECONDS,
	     10 * cronSECONDS,
	     NULL);
  getNetworkLoadUp();
  getNetworkLoadDown();
}

/**
 * Shutdown the status calls module.
 */
void doneStatusCalls() {
  int i;

  if (initialized_ == NO)
    return;
  unregisterConfigurationUpdateCallback(&resetStatusCalls);
  delCronJob(&cronLoadUpdate,
	     10 * cronSECONDS,
	     NULL);
  initialized_ = NO;
#ifdef LINUX
  if (proc_stat != NULL) {
    fclose(proc_stat);
    proc_stat = NULL;
  }
  if (proc_net_dev != NULL) {
    fclose(proc_net_dev);
    proc_net_dev = NULL;
  }
#endif
  for (i=0;i<ifcsSize;i++)
    FREE(ifcs[i].name);
  GROW(ifcs,
       ifcsSize,
       0);
  MUTEX_DESTROY(&statusMutex);
}


/* end of statuscalls.c */

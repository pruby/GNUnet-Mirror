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
 * @file util/os/cpustatus.c
 * @brief calls to determine current network and CPU load
 * @author Tzvetan Horozov
 * @author Christian Grothoff
 * @author Igor Wronsky
 *
 * Status calls implementation for load management.
 */

#include "platform.h"
#include "gnunet_util_os.h"
#include "gnunet_util_error.h"
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

#define DEBUG_STATUSCALLS NO

#ifdef LINUX
static FILE * proc_stat;
#endif

static struct MUTEX * statusMutex;

/**
 * The following routine returns a number between 0-100 (can be larger
 * than 100 if the load is > 1) which indicates the percentage CPU
 * usage.
 *
 * Before its first invocation the method initStatusCalls() must be called.
 * If there is an error the method returns -1
 */
static int updateCpuUsage(){
  int currentLoad;
#ifdef LINUX
  /* under linux, first try %idle/usage using /proc/stat;
     if that does not work, disable /proc/stat for the future
     by closing the file and use the next-best method. */
  if (proc_stat != NULL) {
    static unsigned long long last_cpu_results[4] = { 0, 0, 0, 0 };
    static int have_last_cpu = NO;
    char line[128];
    unsigned long long user_read, system_read, nice_read, idle_read;
    unsigned long long user, system, nice, idle;
    unsigned long long usage_time=0, total_time=1;

    /* Get the first line with the data */
    rewind(proc_stat);
    fflush(proc_stat);
    if (NULL == fgets(line, 128, proc_stat)) {
      GE_LOG_STRERROR_FILE(NULL,
			   GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
			   "fgets",
			   "/proc/stat");
      fclose(proc_stat);
      proc_stat = NULL; /* don't try again */
    } else {
      if (sscanf(line, "%*s %llu %llu %llu %llu",
		 &user_read,
		 &system_read,
		 &nice_read,
		 &idle_read) != 4) {
	GE_LOG_STRERROR_FILE(NULL,
			     GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
			     "fgets-sscanf",
			     "/proc/stat");
	fclose(proc_stat);
	proc_stat = NULL; /* don't try again */
	have_last_cpu = NO;
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
	     (have_last_cpu == YES) ) 
	  currentLoad = (100 * usage_time) / total_time;
	else
	  currentLoad = -1;
	/* Store the values for the next calculation*/
	last_cpu_results[0] = user_read;
	last_cpu_results[1] = system_read;
	last_cpu_results[2] = nice_read;
	last_cpu_results[3] = idle_read;
	have_last_cpu = YES;
	return currentLoad;
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
      GE_LOG_STRERROR(NULL,
		      GE_ERROR | GE_USER | GE_ADMIN | GE_BULK, 
		      "kstat_open");
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
      GE_LOG_STRERROR(NULL,
		      GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
		      "kstat_close");
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
    return currentLoad;
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
	GE_LOG_STRERROR(NULL,
			GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
			"getloadavg");
      }
      currentLoad = -1;
    } else {
      /* success with getloadavg */
      currentLoad = (int) (100 * loadavg);
      return currentLoad;
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

      return currentLoad;
    } else {
      /* only warn once, if there is a problem with
	 NtQuery..., we're going to hit it frequently... */
      static int once;
      if (once == 0) {
	once = 1;
	GE_LOG(NULL,
	       GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
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
	GE_LOG(NULL,
	       GE_USER | GE_ADMIN | GE_ERROR | GE_BULK,
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

    return currentLoad;
  }
#endif

  /* loadaverage not defined and no platform
     specific alternative defined
     => default: error
  */
  return -1;
}


/**
 * Get the load of the CPU relative to what is allowed.
 * @return the CPU load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int os_cpu_get_load(struct GE_Context * ectx,
		    struct GC_Configuration * cfg) {
  static int currentLoad;
  static int lastRet = -1;
  static cron_t lastCall;
  unsigned long long maxCPULoad;
  int ret;
  cron_t now;

  if (-1 == GC_get_configuration_value_number(cfg,
					      "LOAD",
					      "MAXCPULOAD",
					      0,
					      100,
					      100,
					      &maxCPULoad))
    return -1;
  MUTEX_LOCK(statusMutex);
  ret = (100 * currentLoad) / maxCPULoad;
  now = get_time();
  if ( (lastRet != -1) &&
       (now - lastCall < 250 * cronMILLIS) ) {
    /* use smoothing, but do NOT update lastRet at frequencies higher
       than 250ms; this makes the smoothing (mostly) independent from
       the frequency at which getCPULoad is called. */
    ret = (ret + 7 * lastRet)/8;
    MUTEX_UNLOCK(statusMutex);
    return ret;
  }
  currentLoad = updateCpuUsage();
  ret = (100 * currentLoad) / maxCPULoad;
  /* for CPU, we don't do the 'fast increase' since CPU is much
     more jitterish to begin with */
  if (lastRet != -1)
    ret = (ret + 7 * lastRet) / 8;
  lastRet = ret;
  lastCall = now;
  MUTEX_UNLOCK(statusMutex);
  return ret;
}

/**
 * The following method is called in order to initialize the status calls
 * routines.  After that it is safe to call each of the status calls separately
 * @return OK on success and SYSERR on error (or calls errexit).
 */
void __attribute__ ((constructor)) gnunet_cpustats_ltdl_init() {
  statusMutex = MUTEX_CREATE(NO);
#ifdef LINUX
  proc_stat = fopen("/proc/stat", "r");
  if (NULL == proc_stat)
    GE_LOG_STRERROR_FILE(NULL,
			 GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
			 "fopen",
			 "/proc/stat");
#endif
}

/**
 * Shutdown the status calls module.
 */
void __attribute__ ((destructor)) gnunet_cpustats_ltdl_fini() {
#ifdef LINUX
  if (proc_stat != NULL) {
    fclose(proc_stat);
    proc_stat = NULL;
  }
#endif
  MUTEX_DESTROY(statusMutex);
}


/* end of cpustatus.c */

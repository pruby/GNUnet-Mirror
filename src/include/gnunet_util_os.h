/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_os.h
 * @brief low level process routines (fork, IPC,
 *        OS statistics, OS properties)
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_UTIL_OS_H
#define GNUNET_UTIL_OS_H

/* add error and config prototypes */
#include "gnunet_util_config.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * 32-bit timer value.
 */
typedef unsigned int TIME_T;

/**
 * @brief Inter-process semaphore.
 */
struct IPC_SEMAPHORE;

/**
 * @brief plugin (shared library) handle
 */
struct PluginHandle;

/**
 * TIME prototype. "man time".
 */
TIME_T TIME(TIME_T * t);

/**
 * "man ctime_r".
 * @return character sequence describing the time,
 *  must be freed by caller
 */
char * GN_CTIME(const TIME_T * t);

/**
 * @param isDefault is this presumably the default interface
 * @return OK to continue iteration, SYSERR to abort
 */
typedef int (*NetworkIfcProcessor)(const char * name,
				   int isDefault,
				   void * cls);

typedef enum {
  Download,
  Upload,
} NetworkDirection;

struct LoadMonitor;

struct IPC_SEMAPHORE *
IPC_SEMAPHORE_CREATE(struct GE_Context * ectx,
		     const char * basename,
		     unsigned int initialValue);

void IPC_SEMAPHORE_DESTROY(struct IPC_SEMAPHORE * sem);

void IPC_SEMAPHORE_UP(struct IPC_SEMAPHORE * sem);

/**
 * @return OK on success, SYSERR if would block
 */
int IPC_SEMAPHORE_DOWN(struct IPC_SEMAPHORE * sem,
		       int mayBlock);

/**
 * Load plugin
 */
struct PluginHandle *
os_plugin_load(struct GE_Context * ectx,
	       const char * libprefix,
	       const char * dsoname);

/**
 * Try resolving a function provided by the plugin
 * @param logError YES if failure to find the function
 *        is an error that should be logged
 * @param methodprefix prefix for the method; the
 *        method name will be automatically extended
 *        with the respective dsoname of the plugin
 * @return NULL on error, otherwise pointer to the function
 */
void *
os_plugin_resolve_function(struct PluginHandle * plugin,			
			   const char * methodprefix,
			   int logError);

void os_plugin_unload(struct PluginHandle * plugin);

struct LoadMonitor *
os_network_monitor_create(struct GE_Context * ectx,
			  struct GC_Configuration * cfg);

void os_network_monitor_destroy(struct LoadMonitor * mon);

/**
 * Get the load of the network relative to what is allowed.
 *
 * @return the network load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int os_network_monitor_get_load(struct LoadMonitor * monitor,
				NetworkDirection dir);

/**
 * Get the total amoung of bandwidth this load monitor allows
 * in bytes per second
 *
 * @return the maximum bandwidth in bytes per second, -1 for no limit
 */
unsigned long long os_network_monitor_get_limit(struct LoadMonitor * monitor,
						NetworkDirection dir);

/**
 * Tell monitor to increment the number of bytes sent/received
 */
void os_network_monitor_notify_transmission(struct LoadMonitor * monitor,
					    NetworkDirection dir,
					    unsigned long long delta);

/**
 * @brief Enumerate all network interfaces
 * @param callback the callback function
 */
void os_list_network_interfaces(struct GE_Context * ectx,
				NetworkIfcProcessor proc,
				void * cls);

/**
 * @brief Set maximum number of open file descriptors
 * @return OK on success, SYSERR on error
 */
int os_set_fd_limit(struct GE_Context * ectx,
                    int n);

/**
 * Set our process priority
 * @return OK on success, SYSERR on error
 */
int os_set_process_priority(struct GE_Context * ectx,
			    const char * str);

/**
 * @brief Make "application" start automatically
 *
 * @param testCapability YES to merely probe if the OS has this
 *        functionality (in that case, no actual operation is
 *        performed).  SYSERR is returned if
 *        a) autostart is not supported,
 *        b) the application does not seem to exist
 *        c) the user or group do not exist
 *        d) the user has insufficient permissions for
 *           changing autostart
 *        e) doAutoStart is NO, but autostart is already
 *           disabled
 *        f) doAutoStart is YES, but autostart is already
 *           enabled
 * @param doAutoStart YES to enable autostart of the
 *        application, NO to disable it
 * @param username name of the user account to use
 * @param groupname name of the group to use
 * @returns YES on success, NO if unsupported, SYSERR on failure or one of
 *          these error codes:
 *  Windows
 *    2 SCM could not be opened
 *    3 service could not be created/deleted
 *    4 permissions could not be granted
 *    5 registry could not be accessed
 *    6 service could not be accessed
 *  Unix
 *    2 startup script could not be opened
 */
int os_modify_autostart(struct GE_Context * ectx,
			int testCapability,
			int doAutoStart,
			const char * application,
			const char * username,
			const char * groupname);

/**
 * @brief Add or remove a service account for GNUnet
 *
 * @param testCapability YES to merely probe if the OS has this
 *        functionality (in that case, no actual operation is
 *        performed).  SYSERR is returned if
 *        a) adding users is not supported,
 *        b) the user has insufficient permissions for
 *           adding/removing users
 *        c) doAdd is NO, but user does not exist
 *        d) doAdd is YES, and user already exists
 * @param doAdd YES to add, NO to remove user, SYSERR to
 *        purge (removes user AND group)
 * @param name the name of the user
 * @param group name of the group
 * @return OK on success, SYSERR on error
 */
int os_modify_user(int testCapability,
		   int doAdd,
		   const char * name,
		   const char * group);

/**
 * Change current process to run as the given
 * user
 * @return OK on success, SYSERR on error
 */
int os_change_user(struct GE_Context * ectx,
		   const char * user);

/**
 * @brief Change owner of a file
 */
int os_change_owner(struct GE_Context * ectx,
		    const char * filename,
		    const char * user);

/**
 * Get the current CPU load.
 * @param ectx for error reporting
 * @param cfg to determine acceptable load level (LOAD::MAXCPULOAD)
 * @return -1 on error, otherwise load value (between 0 and 100,
 *        (100 is equivalent to full load for one CPU)
 */
int os_cpu_get_load(struct GE_Context * ectx,
		    struct GC_Configuration * cfg);

/**
 * Get the current IO load.
 *
 * @param ectx for error reporting
 * @param cfg to determine acceptable load level (LOAD::MAXIOLOAD)
 * @return -1 on error, otherwise load value (between 0 and 100,
 *       100 means that we spend all of our cycles waiting for
 *       the disk)
 */
int os_disk_get_load(struct GE_Context * ectx,
		     struct GC_Configuration * cfg);

/**
 * Start gnunetd process
 *
 * @param cfgFile configuration file to use, NULL for default
 * @param daemonize YES if gnunetd should be daemonized
 * @return pid_t of gnunetd if NOT daemonized, 0 if
 *  daemonized sucessfully, -1 on error
 */
int os_daemon_start(struct GE_Context * ectx,
		    struct GC_Configuration * cfg,
		    const char * cfgFile,
		    int daemonize);

/**
 * Wait until the gnunet daemon (or any other CHILD process for that
 * matter) with the given PID has terminated.  Assumes that
 * the daemon was started with daemon_start in no-daemonize mode.
 * On arbitrary PIDs, this function may fail unexpectedly.
 *
 * @return YES if gnunetd shutdown with
 *  return value 0, SYSERR if waitpid
 *  failed, NO if gnunetd shutdown with
 *  some error
 */
int os_daemon_stop(struct GE_Context * ectx,
		   int pid);

/**
 * List of install paths
 */
enum InstallPathKind {
  IPK_PREFIX,
  IPK_BINDIR,
  IPK_LIBDIR,
  IPK_DATADIR,
  IPK_LOCALEDIR
};

/**
 * @brief get the path to a specific app dir
 * @author Milan
 * @param ectx the context to report the errors to
 * @param cfg the context to get configuration values from
 * @return a pointer to the dir path (to be freed by the caller)
 */
char * os_get_installation_path(enum InstallPathKind dirkind);

/**
 * Write our process ID to the pid file.  Use only
 * if you are not calling os_terminal_detach, since
 * os_terminal_detach will already write the pid file.
 *
 * @return OK on success, SYSERR on error
 */
int os_write_pid_file(struct GE_Context * ectx,
		      struct GC_Configuration * cfg,
		      unsigned int pid);

/**
 * Delete the PID file (to be called when the daemon
 * shuts down)
 */
int os_delete_pid_file(struct GE_Context * ectx,
		       struct GC_Configuration * cfg);


/**
 * Fork and start a new session to go into the background
 * in the way a good deamon should.  Also writes the PID
 * file.
 *
 * @param filedes pointer to an array of 2 file descriptors
 *        to complete the detachment protocol (handshake)
 */
int os_terminal_detach(struct GE_Context * ectx,
		       struct GC_Configuration * cfg,
		       int * filedes);

/**
 * Complete the handshake of detaching from the terminal.
 * @param success use NO for error, YES for successful start
 */
void os_terminal_detach_complete(struct GE_Context * ectx,
				 int * filedes,
				 int success);

/**
 * @brief Perform OS specific initalization
 * @param ectx logging context, NULL means stderr
 * @returns OK on success, SYSERR otherwise
 */
int os_init(struct GE_Context *ectx);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_OS_H */
#endif
/* end of gnunet_util_os.h */

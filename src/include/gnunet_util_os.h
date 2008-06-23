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
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * 32-bit timer value.
 */
typedef unsigned int GNUNET_Int32Time;

/**
 * @brief Inter-process semaphore.
 */
struct GNUNET_IPC_Semaphore;

/**
 * @brief plugin (shared library) handle
 */
struct GNUNET_PluginHandle;

/**
 * GNUNET_get_time_int32 prototype. "man time".
 */
GNUNET_Int32Time GNUNET_get_time_int32 (GNUNET_Int32Time * t);

/**
 * "man ctime_r".
 * @return character sequence describing the time,
 *  must be freed by caller
 */
char *GNUNET_int32_time_to_string (const GNUNET_Int32Time * t);

/**
 * @param isDefault is this presumably the default interface
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_NetworkInterfaceProcessor) (const char *name,
                                                 int isDefault, void *cls);

typedef enum
{
  GNUNET_ND_DOWNLOAD,
  GNUNET_ND_UPLOAD,
} GNUNET_NETWORK_DIRECTION;

struct GNUNET_LoadMonitor;

struct GNUNET_IPC_Semaphore *GNUNET_IPC_semaphore_create (struct
                                                          GNUNET_GE_Context
                                                          *ectx,
                                                          const char
                                                          *basename,
                                                          unsigned int
                                                          initialValue);

void GNUNET_IPC_semaphore_destroy (struct GNUNET_IPC_Semaphore *sem);

void GNUNET_IPC_semaphore_up (struct GNUNET_IPC_Semaphore *sem);

/**
 * @return GNUNET_OK on success, GNUNET_SYSERR if would block
 */
int GNUNET_IPC_semaphore_down (struct GNUNET_IPC_Semaphore *sem,
                               int mayBlock);

/**
 * Load plugin
 */
struct GNUNET_PluginHandle *GNUNET_plugin_load (struct GNUNET_GE_Context
                                                *ectx, const char *libprefix,
                                                const char *dsoname);

/**
 * Try resolving a function provided by the plugin
 * @param logError GNUNET_YES if failure to find the function
 *        is an error that should be logged
 * @param methodprefix prefix for the method; the
 *        method name will be automatically extended
 *        with the respective dsoname of the plugin
 * @return NULL on error, otherwise pointer to the function
 */
void *GNUNET_plugin_resolve_function (struct GNUNET_PluginHandle *plugin,
                                      const char *methodprefix, int logError);

void GNUNET_plugin_unload (struct GNUNET_PluginHandle *plugin);

struct GNUNET_LoadMonitor *GNUNET_network_monitor_create (struct
                                                          GNUNET_GE_Context
                                                          *ectx,
                                                          struct
                                                          GNUNET_GC_Configuration
                                                          *cfg);

void GNUNET_network_monitor_destroy (struct GNUNET_LoadMonitor *mon);

/**
 * Get the load of the network relative to what is allowed.
 *
 * @return the network load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int GNUNET_network_monitor_get_load (struct GNUNET_LoadMonitor *monitor,
                                     GNUNET_NETWORK_DIRECTION dir);

/**
 * Get the total amoung of bandwidth this load monitor allows
 * in bytes per second
 *
 * @return the maximum bandwidth in bytes per second, -1 for no limit
 */
unsigned long long GNUNET_network_monitor_get_limit (struct GNUNET_LoadMonitor
                                                     *monitor,
                                                     GNUNET_NETWORK_DIRECTION
                                                     dir);

/**
 * Tell monitor to increment the number of bytes sent/received
 */
void GNUNET_network_monitor_notify_transmission (struct GNUNET_LoadMonitor
                                                 *monitor,
                                                 GNUNET_NETWORK_DIRECTION dir,
                                                 unsigned long long delta);

/**
 * @brief Enumerate all network interfaces
 * @param callback the callback function
 */
void GNUNET_list_network_interfaces (struct GNUNET_GE_Context *ectx,
                                     GNUNET_NetworkInterfaceProcessor proc,
                                     void *cls);

/**
 * @brief Set maximum number of open file descriptors
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_set_fd_limit (struct GNUNET_GE_Context *ectx, int n);

/**
 * Set our process priority
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_set_process_priority (struct GNUNET_GE_Context *ectx,
                                 const char *str);

/**
 * @brief Make "application" start automatically
 *
 * @param testCapability GNUNET_YES to merely probe if the OS has this
 *        functionality (in that case, no actual operation is
 *        performed).  GNUNET_SYSERR is returned if
 *        a) autostart is not supported,
 *        b) the application does not seem to exist
 *        c) the user or group do not exist
 *        d) the user has insufficient permissions for
 *           changing autostart
 *        e) doAutoStart is GNUNET_NO, but autostart is already
 *           disabled
 *        f) doAutoStart is GNUNET_YES, but autostart is already
 *           enabled
 * @param doAutoStart GNUNET_YES to enable autostart of the
 *        application, GNUNET_NO to disable it
 * @param servicename name of the service as displayed by the OS
 * @param application path to service binary
 * @param username name of the user account to use
 * @param groupname name of the group to use
 * @returns GNUNET_YES on success, GNUNET_NO if unsupported, GNUNET_SYSERR on failure or one of
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
int
GNUNET_configure_autostart (struct GNUNET_GE_Context *ectx,
                            int testCapability,
                            int doAutoStart,
                            const char *servicename,
                            const char *application,
                            const char *username, const char *groupname);

/**
 * @brief Add or remove a service account for GNUnet
 *
 * @param testCapability GNUNET_YES to merely probe if the OS has this
 *        functionality (in that case, no actual operation is
 *        performed).  GNUNET_SYSERR is returned if
 *        a) adding users is not supported,
 *        b) the user has insufficient permissions for
 *           adding/removing users
 *        c) doAdd is GNUNET_NO, but user does not exist
 *        d) doAdd is GNUNET_YES, and user already exists
 * @param doAdd GNUNET_YES to add, GNUNET_NO to remove user, GNUNET_SYSERR to
 *        purge (removes user AND group)
 * @param name the name of the user
 * @param group name of the group
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_configure_user_account (int testCapability,
                                   int doAdd, const char *name,
                                   const char *group);

/**
 * Change current process to run as the given
 * user
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_change_user (struct GNUNET_GE_Context *ectx, const char *user);

/**
 * @brief Change owner of a file
 */
int GNUNET_file_change_owner (struct GNUNET_GE_Context *ectx,
                              const char *filename, const char *user);

/**
 * Get the current CPU load.
 * @param ectx for error reporting
 * @param cfg to determine acceptable load level (LOAD::MAXCPULOAD)
 * @return -1 on error, otherwise load value (between 0 and 100,
 *        (100 is equivalent to full load for one CPU)
 */
int GNUNET_cpu_get_load (struct GNUNET_GE_Context *ectx,
                         struct GNUNET_GC_Configuration *cfg);

/**
 * Get the current IO load.
 *
 * @param ectx for error reporting
 * @param cfg to determine acceptable load level (LOAD::MAXIOLOAD)
 * @return -1 on error, otherwise load value (between 0 and 100,
 *       100 means that we spend all of our cycles waiting for
 *       the disk)
 */
int GNUNET_disk_get_load (struct GNUNET_GE_Context *ectx,
                          struct GNUNET_GC_Configuration *cfg);

/**
 * Start gnunetd process
 *
 * @param cfgFile configuration file to use, NULL for default
 * @param daemonize GNUNET_YES if gnunetd should be daemonized
 * @return pid_t of gnunetd if NOT daemonized, 0 if
 *  daemonized sucessfully, -1 on error
 */
int GNUNET_daemon_start (struct GNUNET_GE_Context *ectx,
                         struct GNUNET_GC_Configuration *cfg,
                         const char *cfgFile, int daemonize);

/**
 * Wait until the gnunet daemon (or any other CHILD process for that
 * matter) with the given PID has terminated.  Assumes that
 * the daemon was started with daemon_start in no-daemonize mode.
 * On arbitrary PIDs, this function may fail unexpectedly.
 *
 * @return GNUNET_YES if gnunetd shutdown with
 *  return value 0, GNUNET_SYSERR if waitpid
 *  failed, GNUNET_NO if gnunetd shutdown with
 *  some error
 */
int GNUNET_daemon_stop (struct GNUNET_GE_Context *ectx, int pid);

/**
 * List of install paths
 */
enum GNUNET_INSTALL_PATH_KIND
{
  GNUNET_IPK_PREFIX,
  GNUNET_IPK_BINDIR,
  GNUNET_IPK_LIBDIR,
  GNUNET_IPK_DATADIR,
  GNUNET_IPK_LOCALEDIR
};

/**
 * @brief get the path to a specific app dir
 * @author Milan
 * @param ectx the context to report the errors to
 * @param cfg the context to get configuration values from
 * @return a pointer to the dir path (to be freed by the caller)
 */
char *GNUNET_get_installation_path (enum GNUNET_INSTALL_PATH_KIND dirkind);

/**
 * Write our process ID to the pid file.  Use only
 * if you are not calling GNUNET_terminal_detach, since
 * GNUNET_terminal_detach will already write the pid file.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_pid_file_write (struct GNUNET_GE_Context *ectx,
                           struct GNUNET_GC_Configuration *cfg,
                           unsigned int pid,
                           const char *section,
                           const char *value, const char *def);

/**
 * Delete the PID file (to be called when the daemon
 * shuts down)
 */
int GNUNET_pid_file_delete (struct GNUNET_GE_Context *ectx,
                            struct GNUNET_GC_Configuration *cfg,
                            const char *section,
                            const char *value, const char *def);

/**
 * Kill the process that wrote the current PID file
 * (and try to wait for it to terminate).
 * 
 * @return GNUNET_OK kill successful
 *         GNUNET_NO no PID file exists
 *         GNUNET_SYSERR kill seems to have failed
 */
int GNUNET_pid_file_kill_owner (struct GNUNET_GE_Context *ectx,
                                struct GNUNET_GC_Configuration *cfg,
                                const char *section,
                                const char *value, const char *def);


/**
 * Fork and start a new session to go into the background
 * in the way a good daemon should.  Also writes the PID
 * file.
 *
 * @param section section in the configuration for the PID filename
 * @param value value in the configuration for the PID filename
 * @param filedes pointer to an array of 2 file descriptors
 *        to complete the detachment protocol (handshake)
 */
int GNUNET_terminal_detach (struct GNUNET_GE_Context *ectx,
                            struct GNUNET_GC_Configuration *cfg,
                            int *filedes,
                            const char *section,
                            const char *value, const char *def);

/**
 * Complete the handshake of detaching from the terminal.
 * @param success use GNUNET_NO for error, GNUNET_YES for successful start
 */
void GNUNET_terminal_detach_complete (struct GNUNET_GE_Context *ectx,
                                      int *filedes, int success);

/**
 * @brief Perform OS specific initalization
 * @param ectx logging context, NULL means stderr
 * @returns GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int GNUNET_os_init (struct GNUNET_GE_Context *ectx);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_OS_H */
#endif
/* end of gnunet_util_os.h */

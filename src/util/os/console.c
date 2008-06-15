/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/os/console.c
 * @brief code to detach from console
 * @author Christian Grothoff
 *
 * Helper code for writing proper termination code when an application
 * receives a SIGTERM/SIGHUP etc.
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_util_os.h"
#include "gnunet_util_threads.h"
#include "gnunet_util_error.h"
#include "gnunet_util_string.h"
#include "gnunet_util_disk.h"


static char *
getPIDFile (struct GNUNET_GC_Configuration *cfg,
            const char *section, const char *value, const char *def)
{
  char *pif;

  GNUNET_GC_get_configuration_value_filename (cfg, section, value, def, &pif);
  return pif;
}


/**
 * Write our process ID to the pid file.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_pid_file_write (struct GNUNET_GE_Context *ectx,
                       struct GNUNET_GC_Configuration *cfg,
                       unsigned int pid,
                       const char *section,
                       const char *value, const char *def)
{
  FILE *pidfd;
  char *pif;
  char *user;
  char *rdir;
  int len;

  pif = getPIDFile (cfg, section, value, def);
  if (pif == NULL)
    return GNUNET_OK;           /* no PID file */
  GNUNET_GC_get_configuration_value_string (cfg, "GNUNETD", "USER", "",
                                            &user);
  rdir = GNUNET_strdup (pif);
  len = strlen (rdir);
  while ((len > 0) && (rdir[len] != DIR_SEPARATOR))
    len--;
  rdir[len] = '\0';
  if (0 != ACCESS (rdir, F_OK))
    {
      /* we get to create a directory -- and claim it
         as ours! */
      GNUNET_disk_directory_create (ectx, rdir);
      if (strlen (user))
        GNUNET_file_change_owner (ectx, rdir, user);
    }
  if (0 != ACCESS (rdir, W_OK | X_OK))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "access",
                                   rdir);
      GNUNET_free (rdir);
      GNUNET_free (user);
      return GNUNET_SYSERR;
    }
  GNUNET_free (rdir);
  pidfd = FOPEN (pif, "w");
  if (pidfd == NULL)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                   GNUNET_GE_BULK, "fopen", pif);
      GNUNET_free (pif);
      GNUNET_free (user);
      return GNUNET_SYSERR;
    }
  if (0 > FPRINTF (pidfd, "%u", pid))
    GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                 GNUNET_GE_BULK, "fprintf", pif);
  if (0 != fclose (pidfd))
    GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                 GNUNET_GE_BULK, "fclose", pif);
  if (strlen (user))
    GNUNET_file_change_owner (ectx, pif, user);
  GNUNET_free (user);
  GNUNET_free (pif);
  return GNUNET_OK;
}

/**
 * Write our process ID to the pid file.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_pid_file_kill_owner (struct GNUNET_GE_Context *ectx,
                            struct GNUNET_GC_Configuration *cfg,
                            const char *section,
                            const char *value, const char *def)
{
  FILE *pidfd;
  char *pif;
  unsigned int pid;
  unsigned int attempt;
  struct stat sbuf;

  pif = getPIDFile (cfg, section, value, def);
  if (pif == NULL)
    return GNUNET_OK;           /* no PID file */
  pidfd = FOPEN (pif, "r");
  if (pidfd == NULL)
    {
      GNUNET_free (pif);
      return GNUNET_NO;
    }
  if (1 != FSCANF (pidfd, "%u", &pid))
    {
      fclose (pidfd);
      GNUNET_free (pif);
      return GNUNET_SYSERR;
    }
  fclose (pidfd);
  errno = 0;
  if ((0 != KILL (pid, SIGTERM)) && (errno != ESRCH))
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_BULK, "kill");
      GNUNET_free (pif);
      return GNUNET_SYSERR;
    }
  if (errno == 0)
    {
      attempt = 0;
      while ((0 == STAT (pif, &sbuf)) &&
             (GNUNET_shutdown_test () == GNUNET_NO) && (attempt < 200))
        {
          /* wait for at most 10 seconds */
          GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
          attempt--;
        }
      if (0 != STAT (pif, &sbuf))
        {
          GNUNET_free (pif);
          return GNUNET_OK;
        }
      if (0 != KILL (pid, SIGKILL))
        {
          GNUNET_GE_LOG_STRERROR (ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                  GNUNET_GE_BULK, "kill");
          GNUNET_free (pif);
          return GNUNET_SYSERR;
        }
    }
  if (0 != UNLINK (pif))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                   GNUNET_GE_BULK, "unlink", pif);
      GNUNET_free (pif);
      return GNUNET_SYSERR;
    }
  GNUNET_free (pif);
  return GNUNET_OK;
}


int
GNUNET_pid_file_delete (struct GNUNET_GE_Context *ectx,
                        struct GNUNET_GC_Configuration *cfg,
                        const char *section,
                        const char *value, const char *def)
{
  char *pif = getPIDFile (cfg, section, value, def);
  if (pif == NULL)
    return GNUNET_OK;           /* no PID file */
  if (GNUNET_YES == GNUNET_disk_file_test (ectx, pif))
    {
      if (0 != UNLINK (pif))
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                       GNUNET_GE_BULK, "unlink", pif);
          GNUNET_free (pif);
          return GNUNET_SYSERR;
        }
    }
  GNUNET_free (pif);
  return GNUNET_OK;
}


/**
 * Fork and start a new session to go into the background
 * in the way a good deamon should.
 *
 * @param filedes pointer to an array of 2 file descriptors
 *        to complete the detachment protocol (handshake)
 */
int
GNUNET_terminal_detach (struct GNUNET_GE_Context *ectx,
                        struct GNUNET_GC_Configuration *cfg, int *filedes,
                        const char *section,
                        const char *value, const char *def)
{
  pid_t pid;
  int nullfd;

  /* Don't hold the wrong FS mounted */
  if (CHDIR ("/") < 0)
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_FATAL | GNUNET_GE_USER |
                              GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE, "chdir");
      return GNUNET_SYSERR;
    }

#ifndef MINGW
  PIPE (filedes);
  pid = fork ();
  if (pid < 0)
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_FATAL | GNUNET_GE_USER |
                              GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE, "fork");
      return GNUNET_SYSERR;
    }
  if (pid)
    {                           /* Parent */
      int ok;
      char c;

      if (0 != CLOSE (filedes[1]))
        GNUNET_GE_LOG_STRERROR (ectx,
                                GNUNET_GE_WARNING | GNUNET_GE_USER |
                                GNUNET_GE_BULK, "close");
      ok = GNUNET_SYSERR;
      while (0 < READ (filedes[0], &c, sizeof (char)))
        {
          if (c == '.')
            ok = GNUNET_OK;
        }
      fflush (stdout);
      if (ok == GNUNET_OK)
        {
          GNUNET_pid_file_write (ectx, cfg, pid, section, value, def);
          exit (0);
        }
      else
        {
          exit (1);             /* child reported error */
        }
    }
  if (0 != CLOSE (filedes[0]))
    GNUNET_GE_LOG_STRERROR (ectx,
                            GNUNET_GE_WARNING | GNUNET_GE_USER |
                            GNUNET_GE_BULK, "close");
  nullfd = GNUNET_disk_file_open (ectx, "/dev/null", O_RDWR | O_APPEND);
  if (nullfd < 0)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_FATAL | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                                   "fork", "/dev/null");
      return GNUNET_SYSERR;
    }
  /* child - close fds linking to invoking terminal, but
   * close usual incoming fds, but redirect them somewhere
   * useful so the fds don't get reallocated elsewhere.
   */
  if (dup2 (nullfd, 0) < 0 || dup2 (nullfd, 1) < 0 || dup2 (nullfd, 2) < 0)
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_FATAL | GNUNET_GE_USER |
                              GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE, "dup2");
      return GNUNET_SYSERR;
    }
  pid = setsid ();              /* Detach from controlling terminal */
  if (pid == -1)
    GNUNET_GE_LOG_STRERROR (ectx,
                            GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_ADMIN
                            | GNUNET_GE_IMMEDIATE, "setsid");
#else
  FreeConsole ();
#endif
  return GNUNET_OK;
}

void
GNUNET_terminal_detach_complete (struct GNUNET_GE_Context *ectx,
                                 int *filedes, int success)
{
#ifndef MINGW
  char c = '.';

  if (!success)
    c = '!';
  WRITE (filedes[1], &c, sizeof (char));        /* signal success */
  if (0 != CLOSE (filedes[1]))
    GNUNET_GE_LOG_STRERROR (ectx,
                            GNUNET_GE_WARNING | GNUNET_GE_USER |
                            GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE, "close");
#endif
}

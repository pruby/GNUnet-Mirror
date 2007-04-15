/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/os/user.c
 * @brief wrappers for UID functions
 * @author Christian Grothoff
 */

#include "gnunet_util_os.h"
#include "gnunet_util_string.h"
#include "platform.h"

int os_modify_user(int testCapability,
		   int doAdd,		
		   const char *group_name,
		   const char *user_name) {
  int haveGroup;

  if (testCapability) {
    /* TODO: actually check that group/user
       exists/does not yet exist */
#ifdef WINDOWS
    return IsWinNT() ? OK : SYSERR;
#endif
#ifdef LINUX
    if (geteuid() != 0)
      return SYSERR;
    if (doAdd == YES) {
      if ( ( (ACCESS("/usr/sbin/adduser", X_OK) == 0) ||
	     (ACCESS("/usr/sbin/useradd", X_OK) == 0) ) &&
	   ( (ACCESS("/usr/sbin/addgroup", X_OK) == 0) ||
	     (ACCESS("/usr/sbin/groupadd", X_OK) == 0) ) )
	return OK;
      return SYSERR;
    } else if (doAdd == NO) {
      if ( (ACCESS("/usr/sbin/deluser", X_OK) == 0) ||
	   (ACCESS("/usr/sbin/userdel", X_OK) == 0) )
	return OK;
      return SYSERR;
    } else if (doAdd == SYSERR) {
      if ( ( (ACCESS("/usr/sbin/dleuser", X_OK) == 0) ||
	     (ACCESS("/usr/sbin/userdel", X_OK) == 0) ) &&
	   ( (ACCESS("/usr/sbin/delgroup", X_OK) == 0) ||
	     (ACCESS("/usr/sbin/groupdel", X_OK) == 0) ) )
	return OK;
      return SYSERR;
    }
#endif
    return SYSERR;
  }
  if ( (user_name == NULL) ||
       (0 == strlen(user_name)) )
    return 0;

#ifdef WINDOWS
  if (IsWinNT())
    return CreateServiceAccount(user_name,
				"GNUnet service account");
#else
  if (ACCESS("/usr/sbin/adduser",
	     X_OK) == 0) {
    /* Debian */
    /* TODO: FreeBSD? http://www.freebsd.org/cgi/man.cgi?query=adduser&sektion=8 */
    char * cmd;

    haveGroup = group_name && strlen(group_name) > 0;		
    cmd = MALLOC(256 + (haveGroup ? strlen(group_name) : 0) + strlen(user_name));

    if (haveGroup) {
      sprintf(cmd,
	      "/usr/sbin/addgroup --quiet --system %s",
	      group_name);		
      system(cmd);
    }

    sprintf(cmd,
	    "/usr/sbin/adduser --quiet --system %s %s "
	    "--no-create-home %s",
	    haveGroup ? "--ingroup" : "",
	    haveGroup ? group_name : "",
	    user_name);
    system(cmd);
    FREE(cmd);
    return OK;
  }
  /* TODO: useradd */
  else
    return SYSERR;
#endif
  return SYSERR;
}



/**
 * @brief Change user ID
 */
int os_change_user(struct GE_Context * ectx,
		   const char * user) {
#ifndef MINGW
  struct passwd * pws;

  pws = getpwnam(user);
  if (pws == NULL) {
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE,
	   _("Cannot obtain information about user `%s': %s\n"),
	   user,
	   STRERROR(errno));
    return SYSERR;
  }
  if((0 != setgid(pws->pw_gid)) ||
     (0 != setegid(pws->pw_gid)) ||
#if HAVE_INITGROUPS
     (0 != initgroups(user, pws->pw_gid)) ||
#endif
     (0 != setuid(pws->pw_uid)) || (0 != seteuid(pws->pw_uid))) {
    if((0 != setregid(pws->pw_gid, pws->pw_gid)) ||
       (0 != setreuid(pws->pw_uid, pws->pw_uid))) {
      GE_LOG(ectx,
	     GE_FATAL | GE_USER | GE_ADMIN | GE_IMMEDIATE,
	     _("Cannot change user/group to `%s': %s\n"),
	     user,
	     STRERROR(errno));
      return SYSERR;
    }
  }
#endif

  return OK;
}



/**
 * @brief Change owner of a file
 */
int os_change_owner(struct GE_Context * ectx,
		    const char * filename,
		    const char * user) {
#ifndef MINGW
  struct passwd * pws;

  pws = getpwnam(user);
  if (pws == NULL) {
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE,
	   _("Cannot obtain information about user `%s': %s\n"),
	   user,
	   STRERROR(errno));
    return SYSERR;
  }
  if (0 != chown(filename,
		 pws->pw_uid,
		 pws->pw_gid))
    GE_LOG_STRERROR_FILE(ectx,
			 GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE,
			 "chown",
			 filename);
#endif
  return OK;
}



/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/indexinfo.c
 * @brief information about indexed files
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "gnunet_getoption_lib.h"

/**
 * Test if a file is indexed.
 *
 * @return YES if the file is indexed, NO if not, SYSERR on errors
 *  (i.e. filename could not be accessed and thus we have problems
 *  checking; also possible that the file was modified after indexing;
 *  in either case, if SYSERR is returned the user should probably
 *  be notified that 'something is wrong')
 */
int ECRS_isFileIndexed(const char * filename) {
  HashCode512 hc;
  GNUNET_TCP_SOCKET * sock;
  int ret;

  if (SYSERR == getFileHash(filename,
			    &hc))
    return SYSERR;
  sock = getClientSocket();
  if (sock == NULL)
    return SYSERR;
  ret = FS_testIndexed(sock,
		       &hc);
  releaseClientSocket(sock);
  return ret;
}

struct iiC {
  ECRS_FileIterator iterator;
  void * closure;
  int cnt;
};

static int iiHelper(const char * fn,
		    const char * dir,
		    void * ptr) {
  struct iiC * cls = ptr;
  char * fullName;
  char * lnkName;
  unsigned int size;
  int ret;

  fullName = MALLOC(strlen(dir) + strlen(fn) + 4);
  strcpy(fullName, dir);
  strcat(fullName, DIR_SEPARATOR_STR);
  strcat(fullName, fn);
  size = 256;
  lnkName = MALLOC(size);
  while (1) {
    ret = READLINK(fullName,
		   lnkName,
		   size - 1);
    if (ret == -1) {
      if (errno == ENAMETOOLONG) {
	if (size * 2 < size) {
	  FREE(lnkName);
	  FREE(fullName);
	  return OK; /* error */
	}
	GROW(lnkName,
	     size,
	     size * 2);
	continue;
      }
      if (errno != EINVAL) {
	LOG_FILE_STRERROR(LOG_WARNING,
			  "readlink",
			  fullName);
      }
      FREE(lnkName);
      FREE(fullName);
      return OK; /* error */
    } else {
      lnkName[ret] = '\0';
      break;
    }
  }
  cls->cnt++;
  if (OK != cls->iterator(lnkName,
			  cls->closure)) {
    cls->cnt = SYSERR;
    FREE(fullName);
    FREE(lnkName);
    return SYSERR;
  }
  FREE(fullName);
  FREE(lnkName);
  return OK;
}

/**
 * Iterate over all indexed files.
 *
 * This function will ONLY work if gnunetd runs on the
 * same machine as the current process and if the indexed
 * files could be symlinked.  If indexed files had to be
 * uploaded to a remote machine or copied, the original
 * names will have been lost.  In that case, the iterator
 * will NOT iterate over these files.
 *
 * @return number of files indexed, SYSERR if iterator aborted
 */
int ECRS_iterateIndexedFiles(ECRS_FileIterator iterator,
			     void * closure) {
  char * tmp;
  char * indexDirectory;
  GNUNET_TCP_SOCKET * sock;
  struct iiC cls;

  sock = getClientSocket();
  if (sock == NULL)
    return 0;
  tmp = getConfigurationOptionValue(sock,
				    "FS",
				    "INDEX-DIRECTORY");
  releaseClientSocket(sock);
  if (tmp == NULL) {
    return 0;
  }
  indexDirectory = expandFileName(tmp);
  FREE(tmp);
  cls.iterator = iterator;
  cls.closure = closure;
  cls.cnt = 0;
  scanDirectory(indexDirectory,
		&iiHelper,
		&cls);
  FREE(indexDirectory);
  return cls.cnt;
}

/* end of indexinfo.c */

/*
     This file is part of GNUnet

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
 * @file src/applications/afs/gtkui/resume.c
 * @brief code that handles resuming aborted downloads
 * @author Nils Durner
 */

#include <string.h>
#ifdef MINGW
  #include <fcntl.h>
  #include <io.h>
#else
  #include <sys/file.h>
#endif
#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_afs_esed2.h"

/**
 * Every download is stored in ~/.gnunet/afs-downloads.dat
 * in the format "%s\t%s\n" (uri, filename)
 */

/**
 * @brief Return the filename of the file that contains the list of unfinished downloads
 * @return the filename (caller frees)
 */ 
char *getResumeFile() {
  char *fn, *basename, *exp;

  basename = getConfigurationString("", "GNUNET_HOME");
  exp = expandFileName(basename);
  fn = MALLOC(strlen(exp) + 19);
  sprintf(fn, "%s/afs-downloads.dat", exp);
  FREE(basename);

  return fn;
}

/**
 * @brief Open the file that contains the list of unfinished downloads
 * @return filedescriptor of the file, -1 on error
 */
int openResumeFile(int op) {
  char *fn;
  int ret;
  
  fn = getResumeFile();
  ret = OPEN(fn, op, S_IRUSR | S_IWUSR);
  FREE(fn);
  
  return ret;
}

/**
 * @brief Add a download to the list of unfinished downloads
 * @param uri GNUnet AFS URI
 * @param fileName the filename (max MAX_FILENAME_LEN)
 * @return SYSERR on error,  YES on success
**/
int storeResumeInfo(char *uri, char *fileName)
{
  int resumeFile;
  char *resumeURI;
  int uriLen, isNoted, bytesRead;

  uriLen = strlen(uri);
  
  if ((resumeFile = openResumeFile(O_APPEND | O_CREAT | O_RDWR)) != -1) {
    
    flock(resumeFile, LOCK_EX);
    
    /* Check whether we already have this URI on our list */
    resumeURI = (char *) MALLOC(uriLen + 1);
    isNoted = 0;
    bytesRead = 1;
    while (bytesRead > 0 && isNoted == 0) {
      /* read a URI from the file */
      bytesRead = READ(resumeFile, resumeURI, uriLen);
      resumeURI[uriLen] = 0;
      /* is it the URI to be added? */
      if (strcmp(resumeURI, uri) == 0)
        isNoted = 1;
      
      /* Skip filename */
      while (bytesRead > 0 && *resumeURI != '\n')
        bytesRead = READ(resumeFile, resumeURI, 1);
    }
    FREE(resumeURI);
    
    /* Add the download to the list if it isn't already there */
    if (!isNoted) {
      int fnLen, len;
      
      fnLen = strlen(fileName);
      len = uriLen + fnLen + 2;
      if (fnLen > MAX_FILENAME_LEN) {
        flock(resumeFile, LOCK_UN);
        CLOSE(resumeFile);
        
        return SYSERR;
      } else {
        resumeURI = MALLOC(len + 1);
        sprintf(resumeURI, "%s\t%s\n", uri, fileName);
        WRITE(resumeFile, resumeURI, len);
        FREE(resumeURI);
      }
    }
      
    flock(resumeFile, LOCK_UN);
    CLOSE(resumeFile);
  } else
    return SYSERR;
  
  return YES;
}

/**
 * @brief Resume all aborted downloads
 * @param dl download function
 * @return SYSERR on error, YES on success
 */
int resumeDownloads(TDownloadURI dl) {
  int resumeFile;
  
  if ((resumeFile = openResumeFile(O_CREAT | O_RDONLY)) != -1) {
    
    char *uri, *fn, *c;
    unsigned int uriLen, fnLen, readURI;
    int bytesRead;
    
    uri = (char *) MALLOC(251);
    fn = (char *) MALLOC(MAX_FILENAME_LEN + 2);
    
    flock(resumeFile, LOCK_EX);

    /* Every line starts with the URI */
    c = uri;
    readURI = 1;
    uriLen = fnLen = 0;
    bytesRead = 1;
    while(bytesRead > 0) {
      bytesRead = READ(resumeFile, c, 1);
      switch (*c) {
        case '\t':
          /* The tab delimits the URI and the filename */
          *c = 0;
          c = fn;
          readURI = 0;
          fnLen = 0;
          break;
        case '\n':
          *c = 0;
          /* We have all information needed, start download */
          flock(resumeFile, LOCK_UN);
          dl(uri, fn);
          flock(resumeFile, LOCK_EX);

          /* init to get next download */
          c = uri;
          *fn = 0;
          readURI = 1;
          uriLen = 0;
          break;
        default:
          c++;
      }
      
      /* Don't overflow our buffers */
      if (readURI) {
        uriLen++;
        if (uriLen > 250)
          break; /* should not happen! */
      } else {
        fnLen++;
        if (fnLen > MAX_FILENAME_LEN)
          break; /* should not happen! */
      }
    }
    
    flock(resumeFile, LOCK_UN);
    CLOSE(resumeFile);
  } else
    return SYSERR;
    
  return YES;
}

/**
 * @brief Remove a download from the list of unfinished downloads
 * @param uri the download's GNUnet AFS uri
 * @return SYSERR on error, YES on success
 */
int removeResumeInfo(char *uri) {
  int resumeFile;
  char *resumeURI;
  int uriLen, dlIndex, bytesRead;

  uriLen = strlen(uri);
  
  if ((resumeFile = openResumeFile(O_CREAT | O_RDWR)) != -1) {
    
    flock(resumeFile, LOCK_EX);
    resumeURI = (char *) MALLOC(uriLen + 1);
    dlIndex = -1;
    bytesRead = 1;
    while (bytesRead > 0 && dlIndex == -1 ) {
      /* Read a URI */
      bytesRead = READ(resumeFile, resumeURI, uriLen);
      resumeURI[uriLen] = 0;
      
      /* Is this the download to be removed? */
      if (strcmp(resumeURI, uri) == 0)
        /* current file position - length of the URI */
        dlIndex = lseek(resumeFile, 0, SEEK_CUR) - uriLen;
      
      /* Skip filename */
      while (bytesRead > 0 && *resumeURI != '\n')
        bytesRead = READ(resumeFile, resumeURI, 1);
    }
    FREE(resumeURI);
    
    /* Remove the download from the list */
    if (dlIndex > -1) {
      int tailLen, tailBegin, fLen;
      char *tail, *resumeFN = getResumeFile();

      /* Read the rest of the file behind the line of the download we want to remove */
      tailBegin = lseek(resumeFile, 0, SEEK_CUR);
      fLen = getFileSize(resumeFN);
      FREE(resumeFN);
      tailLen = fLen - tailBegin;
      tail = (char *) MALLOC(tailLen + 1);
      READ(resumeFile, tail, tailLen);
      /* Seek back to the beginning of the line to remove */
      lseek(resumeFile, dlIndex, SEEK_SET);
      /* Write out the data block behind the line */
      WRITE(resumeFile, tail, tailLen);
      FREE(tail);
      fsync(resumeFile);
      /* Truncate file */
      ftruncate(resumeFile, fLen - (tailBegin - dlIndex));
    }
    
    flock(resumeFile, LOCK_UN);
    CLOSE(resumeFile);
  } else
    return SYSERR;
    
  return YES;
}

/* end of resume.c */

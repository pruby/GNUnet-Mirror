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
 * This module is responsible for storing the names 
 * of indexed files.
 *
 * @file applications/afs/module/fileindex.h
 * @author Christian Grothoff
 */

#ifndef FILEINDEX_H
#define FILEINDEX_H

#include "afs.h"

/**
 * Callback for each indexed file.
 *
 * @param fn the name of the file
 * @param idx the index of the file
 * @param data opaque context pointer for the callee
 * @return SYSERR if the file should be removed from the list
 */
typedef int (*IndexedFileNameCallback)(const char * fn,
				       unsigned short idx,
				       void * data);

/**
 * Initialize the fileindex module.
 */
void initFileIndex();

/**
 * Shutdown the fileindex module.
 */
void doneFileIndex();

/**
 * Get the name of an indexed file.
 *
 * @param index the index of the file
 * @return the filename (caller frees)
 */
char * getIndexedFileName(unsigned short index);

/**
 * Add a name to the list of indexed filenames.
 * @param filename the name of the new file
 * @return the index of that file in the list, -1 on error
 */
int appendFilename(const char * filename);

/**
 * Invoke a method on each of the filenames of the indexed files. If
 * the method returns SYSERR, the file is removed from the list of
 * indexed files!
 *
 * @param method the method to invoke for each indexed file 
 * @param data the last argument to method
 * @return the number of shared files (after changes caused
 *          by this call)
 */
int forEachIndexedFile(IndexedFileNameCallback method,
		       void * data);

#endif
/* end of fileindex.h */

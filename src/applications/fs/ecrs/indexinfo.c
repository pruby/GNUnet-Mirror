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

/**
 * Test if a file is indexed.
 *
 * This function will ONLY work if gnunetd runs on the
 * same machine as the current process and if the indexed
 * files could be symlinked.  If indexed files had to be 
 * uploaded to a remote machine or copied, the original
 * names will have been lost.
 *
 * @return YES if the file is indexed, NO if not, SYSERR on errors
 *  (i.e. filename could not be accessed and thus we have problems
 *  checking; also possible that the file was modified after indexing;
 *  in either case, if SYSERR is returned the user should probably
 *  be notified that 'something is wrong')
 */
int ECRS_isFileIndexed(const char * filename) {
  return SYSERR;
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
  return SYSERR;
}

/* end of indexinfo.c */

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
 * @file applications/afs/module/bloomfilter.h
 * @author Christian Grothoff
 * @author Igor Wronsky
 **/

#ifndef AFS_DB_BLOOMFILTER_H
#define AFS_DB_BLOOMFILTER_H

#include "afs.h"

extern Bloomfilter * superBloomFilter;
extern Bloomfilter * singleBloomFilter;

void initBloomfilters();

void doneBloomfilters();

void bf_deleteEntryCallback(const HashCode160 * key,
			    const ContentIndex * ce,
			    void * data,
			    unsigned int datalen,
			    void * closure);

#endif

/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/esed2/keywords.c
 * @brief encapsulation of libextractor 
 * @author Christian Grothoff
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

#if USE_LIBEXTRACTOR
#include <extractor.h>
#endif

/**
 * Load the extractors as specified by the configuration.
 *
 * @return linked list of extractrs
 */
void * getExtractors() {
#if USE_LIBEXTRACTOR
  char * config;
  EXTRACTOR_ExtractorList * exList;

  exList = EXTRACTOR_loadDefaultLibraries();
  config = getConfigurationString("AFS",
				  "EXTRACTORS");
  if (config != NULL) {
    exList = EXTRACTOR_loadConfigLibraries(exList,
					   config);
    FREE(config); 
    return exList;
  } else
    return exList;
#else
  return NULL;
#endif
}

/**
 * Extract keywords, mime-type and description from a file
 *
 * @param filename the name of the file
 * @param description the description (the user may have
 *        supplied a description already (*description != NULL),
 *        in that case, append, mind the maximum size!
 * @param mimetype the mimetype, again, the user may
 *        have supplied one
 * @param keywords the list of keywords, allocate space at
 *        another location if required, copy existing keywords
 *        over to that space! Do NEVER free *keywords!
 * @param num_keywords the number of keywords in the
 *        existing *keywords array that was passed in.
 *        Set *num_keywords to the new number of keywords!
 */
void extractKeywords(const char * filename,
		     char ** description,
		     char ** mimetype,
		     char *** keywords,
		     int * num_keywords) {
#if USE_LIBEXTRACTOR
  EXTRACTOR_ExtractorList * exList;
  exList = getExtractors();
  extractKeywordsMulti(filename, 
		       description,
		       mimetype, 
		       keywords, 
		       num_keywords, 
		       exList);
  EXTRACTOR_removeAll(exList);
#else
#endif
}

#if USE_LIBEXTRACTOR
#ifndef EXTRACTOR_VERSION
/* pre 0.2.6? */
/**
 * Remove empty (all-whitespace) keywords from the list.
 * @param list the original keyword list (destroyed in the process!)
 * @return a list of keywords without duplicates
 */
static EXTRACTOR_KeywordList *
EXTRACTOR_removeEmptyKeywords (EXTRACTOR_KeywordList * list)
{
  EXTRACTOR_KeywordList * pos;
  EXTRACTOR_KeywordList * last;

  last = NULL;
  pos = list;
  while (pos != NULL)
    {
      int allWhite;
      int i;
      allWhite = 1;
      for (i=strlen(pos->keyword)-1;i>=0;i--)
	if (! isspace(pos->keyword[i]))
	  allWhite = 0;
      if (allWhite) 
	{
	  EXTRACTOR_KeywordList * next;
	  next = pos->next;
	  if (last == NULL)
	    list = next;
	  else
	    last->next = next;
	  free(pos->keyword);
	  free(pos);
	  pos = next;
	}
      else 
	{
	  last = pos;
	  pos = pos->next;
	}
    }
  return list;
}
#endif
#endif

/**
 * Extract keywords, mime-type and description from a file
 *
 * @param filename the name of the file
 * @param description the description (the user may have
 *        supplied a description already (*description != NULL),
 *        in that case, append, mind the maximum size!
 * @param mimetype the mimetype, again, the user may
 *        have supplied one
 * @param keywords the list of keywords, allocate space at
 *        another location if required, copy existing keywords
 *        over to that space! Do NEVER free *keywords!
 * @param num_keywords the number of keywords in the
 *        existing *keywords array that was passed in.
 *        Set *num_keywords to the new number of keywords!
 * @param exListWrap the list of extractors
 */
void extractKeywordsMulti(const char * filename,
			  char ** description,
			  char ** mimetype,
			  char *** keywords,
			  int * num_keywords,
			  void * exListWrap) {
#if USE_LIBEXTRACTOR
  EXTRACTOR_ExtractorList * exList;
  EXTRACTOR_KeywordList * keyList;
  EXTRACTOR_KeywordList * pos;
  char ** newKeywords;
  const char * key;
  int count;
  int i;

  exList = (EXTRACTOR_ExtractorList*) exListWrap;
  keyList = EXTRACTOR_getKeywords(exList, 
				  filename);
  keyList = EXTRACTOR_removeDuplicateKeywords(keyList,
					      EXTRACTOR_DUPLICATES_REMOVE_UNKNOWN);
  keyList = EXTRACTOR_removeEmptyKeywords(keyList);
  if (*mimetype == NULL) {
    key = EXTRACTOR_extractLast(EXTRACTOR_MIMETYPE, keyList);
    if (key != NULL)
      *mimetype = STRDUP(key);
  }
  if (*description == NULL) {
    key = EXTRACTOR_extractLast(EXTRACTOR_DESCRIPTION, keyList);
    if (key != NULL)    
      *description = STRDUP(key);
  }
  keyList = EXTRACTOR_removeDuplicateKeywords(keyList,
					      EXTRACTOR_DUPLICATES_TYPELESS);
  count = EXTRACTOR_countKeywords(keyList);
  newKeywords = (char**) MALLOC((count+(*num_keywords)) * sizeof(char*));
  for (i=0;i<*num_keywords;i++)
    newKeywords[i] = (*keywords)[i];
  pos = keyList;
  for (i=0;i<count;i++) {
    newKeywords[*num_keywords+i] = STRDUP(pos->keyword);
    pos = pos->next;
  }
  /* assert(keyList == NULL); */
  EXTRACTOR_freeKeywords(keyList);
  FREENONNULL(*keywords);
  *keywords = newKeywords;
  *num_keywords = *num_keywords + count;
#else
#endif
}

/* end of keywords.c */

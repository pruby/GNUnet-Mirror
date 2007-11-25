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
 * @file applications/fs/ecrs/helper.c
 * @brief ECRS helper functions
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"

/**
 * Create an ECRS URI from a single user-supplied string of keywords.
 * The string may contain the reserved word 'AND' to create a boolean
 * search over multiple keywords.
 *
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_keyword_string_to_uri (struct GNUNET_GE_Context *ectx,
                                   const char *input)
{
  char **keywords;
  unsigned int num_Words;
  int inWord;
  char *c;
  struct GNUNET_ECRS_URI *uri;
  char *searchString;

  if (input == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  searchString = GNUNET_strdup (input);
  num_Words = 0;
  for (inWord = 0, c = searchString; *c != '\0'; ++c)
    {
      if (isspace (*c))
        {
          inWord = 0;
        }
      else if (!inWord)
        {
          inWord = 1;
          ++num_Words;
        }
    }

  if (num_Words == 0)
    {
      GNUNET_free_non_null (searchString);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                     _("No keywords specified!\n"));
      return NULL;
    }
  keywords = GNUNET_malloc (num_Words * sizeof (char *));
  num_Words = 0;
  for (inWord = 0, c = searchString; *c != '\0'; ++c)
    {
      if (isspace (*c))
        {
          inWord = 0;
          *c = '\0';
        }
      else if (!inWord)
        {
          keywords[num_Words] = c;
          inWord = 1;
          ++num_Words;
        }
    }
  uri =
    GNUNET_ECRS_keyword_command_line_to_uri (ectx, num_Words,
                                             (const char **) keywords);
  GNUNET_free (keywords);
  GNUNET_free (searchString);
  return uri;
}

/**
 * Create an ECRS URI from a user-supplied command line of keywords.
 * The command line may contain the reserved word 'AND' to create a
 * boolean search over multiple keywords.
 *
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_keyword_command_line_to_uri (struct GNUNET_GE_Context *ectx,
                                         unsigned int num_keywords,
                                         const char **keywords)
{
  unsigned int i;
  unsigned int uriLen;
  char *uriString;
  unsigned int uriSize;
  struct GNUNET_ECRS_URI *uri;

  uriString = NULL;
  uriSize = 0;
  GNUNET_array_grow (uriString, uriSize, 4096);
  strcpy (uriString, GNUNET_ECRS_URI_PREFIX);
  strcat (uriString, GNUNET_ECRS_SEARCH_INFIX);
  uriLen =
    1 + strlen (GNUNET_ECRS_URI_PREFIX) + strlen (GNUNET_ECRS_SEARCH_INFIX);


  for (i = 0; i < num_keywords; i++)
    {
      if (uriSize < uriLen + strlen (_("AND")) + 1 + strlen (keywords[i]))
        GNUNET_array_grow (uriString, uriSize,
                           uriSize + 4096 + strlen (keywords[i]));
      if ((i > 0) && (0 == strcmp (keywords[i], _("AND"))))
        {
          strcat (uriString, "+");
          if (i == num_keywords - 1)
            strcat (uriString, _("AND"));       /* last keyword 'AND'? keep it! */
          uriLen += 1;
        }
      else
        {
          if ((i > 0) && (0 != strcmp (keywords[i - 1], _("AND"))))
            {
              strcat (uriString, " ");
              uriLen += 1;
            }
          strcat (uriString, keywords[i]);
          uriLen += strlen (keywords[i]);
        }
    }
  uri = GNUNET_ECRS_string_to_uri (ectx, uriString);
  GNUNET_array_grow (uriString, uriSize, 0);
  return uri;
}

/**
 * Create an ECRS URI from a user-supplied list of keywords.
 * The keywords are NOT separated by AND but already
 * given individually.
 *
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_keyword_list_to_uri (struct GNUNET_GE_Context *ectx,
                                 unsigned int num_keywords,
                                 const char **keywords)
{
  unsigned int i;
  unsigned int uriLen;
  char *uriString;
  unsigned int uriSize;
  struct GNUNET_ECRS_URI *uri;

  uriString = NULL;
  uriSize = 0;
  GNUNET_array_grow (uriString, uriSize, 4096);
  strcpy (uriString, GNUNET_ECRS_URI_PREFIX);
  strcat (uriString, GNUNET_ECRS_SEARCH_INFIX);
  uriLen =
    1 + strlen (GNUNET_ECRS_URI_PREFIX) + strlen (GNUNET_ECRS_SEARCH_INFIX);


  for (i = 0; i < num_keywords; i++)
    {
      if (uriSize < uriLen + 1 + strlen (keywords[i]))
        GNUNET_array_grow (uriString, uriSize,
                           uriSize + 4096 + strlen (keywords[i]));
      if (i > 0)
        {
          strcat (uriString, "+");
          uriLen++;
        }
      strcat (uriString, keywords[i]);
      uriLen += strlen (keywords[i]);
    }
  uri = GNUNET_ECRS_string_to_uri (ectx, uriString);
  GNUNET_array_grow (uriString, uriSize, 0);
  return uri;
}


/* end of helper.c */

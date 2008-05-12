/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
#include "ecrs.h"

/**
 * Create an ECRS URI from a single user-supplied string of keywords.
 * The string is broken up at spaces into individual keywords.
 * Keywords that start with "+" are mandatory.  Double-quotes can
 * be used to prevent breaking up strings at spaces (and also
 * to specify non-mandatory keywords starting with "+").
 *
 * Keywords must contain a balanced number of double quotes and
 * double quotes can not be used in the actual keywords (for
 * example, the string '""foo bar""' will be turned into two
 * "OR"ed keywords 'foo' and 'bar', not into '"foo bar"'.
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
  char *pos;
  struct GNUNET_ECRS_URI *uri;
  char *searchString;
  int saw_quote;

  if (input == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  searchString = GNUNET_strdup (input);
  num_Words = 0;
  inWord = 0;
  saw_quote = 0;
  pos = searchString;
  while ('\0' != *pos)
    {
      if ((saw_quote == 0) && (isspace (*pos)))
        {
          inWord = 0;
        }
      else if (0 == inWord)
        {
          inWord = 1;
          ++num_Words;
        }
      if ('"' == *pos)
        saw_quote = (saw_quote + 1) % 2;
      pos++;
    }
  if (num_Words == 0)
    {
      GNUNET_free (searchString);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                     _("No keywords specified!\n"));
      return NULL;
    }
  if (saw_quote != 0)
    {
      GNUNET_free (searchString);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                     _("Number of double-quotes not balanced!\n"));
      return NULL;
    }
  keywords = GNUNET_malloc (num_Words * sizeof (char *));
  num_Words = 0;
  inWord = 0;
  pos = searchString;
  while ('\0' != *pos)
    {
      if ((saw_quote == 0) && (isspace (*pos)))
        {
          inWord = 0;
          *pos = '\0';
        }
      else if (0 == inWord)
        {
          keywords[num_Words] = pos;
          inWord = 1;
          ++num_Words;
        }
      if ('"' == *pos)
        saw_quote = (saw_quote + 1) % 2;
      pos++;
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
 * Arguments should start with "+" to indicate mandatory
 * keywords.
 *
 * @param argc number of keywords
 * @param argv keywords (double quotes are not required for
 *             keywords containing spaces; however, double
 *             quotes are required for keywords starting with
 *             "+"); there is no mechanism for having double
 *             quotes in the actual keywords (if the user
 *             did specifically specify double quotes, the
 *             caller should convert each double quote
 *             into two single quotes).
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_keyword_command_line_to_uri (struct GNUNET_GE_Context *ectx,
                                         unsigned int num_keywords,
                                         const char **keywords)
{
  unsigned int i;
  struct GNUNET_ECRS_URI *uri;
  const char *keyword;
  char *val;
  const char *r;
  char *w;

  uri = GNUNET_malloc (sizeof (URI));
  uri->type = ksk;
  uri->data.ksk.keywordCount = num_keywords;
  uri->data.ksk.keywords = GNUNET_malloc (num_keywords * sizeof (char *));
  for (i = 0; i < num_keywords; i++)
    {
      keyword = keywords[i];
      if (keyword[0] == '+')
        {
          val = GNUNET_strdup (keyword);
        }
      else
        {
          val = GNUNET_malloc (strlen (keyword) + 2);
          strcpy (val, " ");
          strcat (val, keyword);
        }
      r = val;
      w = val;
      while ('\0' != *r)
        {
          if ('"' == *r)
            r++;
          else
            *(w++) = *(r++);
        }
      uri->data.ksk.keywords[i] = GNUNET_strdup (val);
      GNUNET_free (val);
    }
  return uri;
}

/* end of helper.c */

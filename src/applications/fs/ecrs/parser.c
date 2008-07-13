/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/uri.c
 * @brief Parses keyword and metadata command line options
 * @author Christian Grothoff
 */

#include "platform.h"
#include "ecrs.h"
#include "gnunet_ecrs_lib.h"

/**
 * @param scls must be of type "struct GNUNET_ECRS_URI **"
 */
int
GNUNET_ECRS_getopt_configure_set_keywords (GNUNET_CommandLineProcessorContext
                                           * ctx, void *scls,
                                           const char *option,
                                           const char *value)
{
  struct GNUNET_ECRS_URI **uri = scls;
  struct GNUNET_ECRS_URI *u = *uri;
  char *val;
  size_t slen;

  if (u == NULL)
    {
      u = GNUNET_malloc (sizeof (struct GNUNET_ECRS_URI));
      *uri = u;
      u->type = ksk;
      u->data.ksk.keywordCount = 0;
      u->data.ksk.keywords = NULL;
    }
  else
    {
      GNUNET_GE_ASSERT (NULL, u->type == ksk);
    }
  slen = strlen (value);
  if (slen == 0)
    return GNUNET_SYSERR;       /* cannot be empty */
  if (value[0] == '+')
    {
      /* simply preserve the "mandatory" flag */
      if (slen < 2)
        return GNUNET_SYSERR;   /* empty keywords not allowed */
      if ((value[1] == '"') && (slen > 3) && (value[slen - 1] == '"'))
        {
          /* remove the quotes, keep the '+' */
          val = GNUNET_malloc (slen - 1);
          val[0] = '+';
          memcpy (&val[1], &value[2], slen - 3);
          val[slen - 2] = '\0';
        }
      else
        {
          /* no quotes, just keep the '+' */
          val = GNUNET_strdup (value);
        }
    }
  else
    {
      if ((value[0] == '"') && (slen > 2) && (value[slen - 1] == '"'))
        {
          /* remove the quotes, add a space */
          val = GNUNET_malloc (slen);
          val[0] = ' ';
          memcpy (&val[1], &value[1], slen - 2);
          val[slen - 1] = '\0';
        }
      else
        {
          /* add a space to indicate "not mandatory" */
          val = GNUNET_malloc (slen + 2);
          strcpy (val, " ");
          strcat (val, value);
        }
    }
  GNUNET_array_grow (u->data.ksk.keywords,
                     u->data.ksk.keywordCount, u->data.ksk.keywordCount + 1);
  u->data.ksk.keywords[u->data.ksk.keywordCount - 1] = val;
  return GNUNET_OK;
}


/**
 * @param scls must be of type "struct GNUNET_MetaData **"
 */
int
GNUNET_ECRS_getopt_configure_set_metadata (GNUNET_CommandLineProcessorContext
                                           * ctx, void *scls,
                                           const char *option,
                                           const char *value)
{
  struct GNUNET_MetaData **mm = scls;
  EXTRACTOR_KeywordType type;
  const char *typename;
  const char *typename_i18n;
  struct GNUNET_MetaData *meta;
  char *tmp;

  meta = *mm;
  if (meta == NULL)
    {
      meta = GNUNET_meta_data_create ();
      *mm = meta;
    }

  tmp = GNUNET_convert_string_to_utf8 (NULL, value, strlen (value),
#if ENABLE_NLS
                                       nl_langinfo (CODESET)
#else
                                       "utf-8"
#endif
    );
  type = EXTRACTOR_getHighestKeywordTypeNumber ();
  while (type > 0)
    {
      type--;
      typename = EXTRACTOR_getKeywordTypeAsString (type);
      typename_i18n = dgettext ("libextractor", typename);
      if ((strlen (tmp) >= strlen (typename) + 1) &&
          (tmp[strlen (typename)] == ':') &&
          (0 == strncmp (typename, tmp, strlen (typename))))
        {
          GNUNET_meta_data_insert (meta, type, &tmp[strlen (typename) + 1]);
          GNUNET_free (tmp);
          tmp = NULL;
          break;
        }
      if ((strlen (tmp) >= strlen (typename_i18n) + 1) &&
          (tmp[strlen (typename_i18n)] == ':') &&
          (0 == strncmp (typename_i18n, tmp, strlen (typename_i18n))))
        {
          GNUNET_meta_data_insert (meta, type,
                                   &tmp[strlen (typename_i18n) + 1]);
          GNUNET_free (tmp);
          tmp = NULL;
          break;
        }
    }
  if (tmp != NULL)
    {
      GNUNET_meta_data_insert (meta, EXTRACTOR_UNKNOWN, tmp);
      GNUNET_free (tmp);
      printf (_
              ("Unknown metadata type in metadata option `%s'.  Using metadata type `unknown' instead.\n"),
              value);
    }
  return GNUNET_OK;
}

/* end of parser.c */

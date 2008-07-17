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
#include <limits.h>
#include "gnunet_util.h"
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

  if (num_keywords == 0)
    return NULL;
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
      *w = '\0';
      uri->data.ksk.keywords[i] = GNUNET_strdup (val);
      GNUNET_free (val);
    }
  return uri;
}

static char *mimeMap[][2] = {
  {"application/bz2", ".bz2"},
  {"application/gnunet-directory", ".gnd"},
  {"application/java", ".class"},
  {"application/msword", ".doc"},
  {"application/ogg", ".ogg"},
  {"application/pdf", ".pdf"},
  {"application/pgp-keys", ".key"},
  {"application/pgp-signature", ".pgp"},
  {"application/postscript", ".ps"},
  {"application/rar", ".rar"},
  {"application/rtf", ".rtf"},
  {"application/xml", ".xml"},
  {"application/x-debian-package", ".deb"},
  {"application/x-dvi", ".dvi"},
  {"applixation/x-flac", ".flac"},
  {"applixation/x-gzip", ".gz"},
  {"application/x-java-archive", ".jar"},
  {"application/x-java-vm", ".class"},
  {"application/x-python-code", ".pyc"},
  {"application/x-redhat-package-manager", ".rpm"},
  {"application/x-rpm", ".rpm"},
  {"application/x-tar", ".tar"},
  {"application/x-tex-pk", ".pk"},
  {"application/x-texinfo", ".texinfo"},
  {"application/x-xcf", ".xcf"},
  {"application/x-xfig", ".xfig"},
  {"application/zip", ".zip"},

  {"audio/midi", ".midi"},
  {"audio/mpeg", ".mp3"},
  {"audio/real", ".rm"},
  {"audio/x-wav", ".wav"},

  {"image/gif", ".gif"},
  {"image/jpeg", ".jpg"},
  {"image/pcx", ".pcx"},
  {"image/png", ".png"},
  {"image/tiff", ".tiff"},
  {"image/x-ms-bmp", ".bmp"},
  {"image/x-xpixmap", ".xpm"},

  {"text/css", ".css"},
  {"text/html", ".html"},
  {"text/plain", ".txt"},
  {"text/rtf", ".rtf"},
  {"text/x-c++hdr", ".h++"},
  {"text/x-c++src", ".c++"},
  {"text/x-chdr", ".h"},
  {"text/x-csrc", ".c"},
  {"text/x-java", ".java"},
  {"text/x-moc", ".moc"},
  {"text/x-pascal", ".pas"},
  {"text/x-perl", ".pl"},
  {"text/x-python", ".py"},
  {"text/x-tex", ".tex"},

  {"video/avi", ".avi"},
  {"video/mpeg", ".mpeg"},
  {"video/quicktime", ".qt"},
  {"video/real", ".rm"},
  {"video/x-msvideo", ".avi"},
  {NULL, NULL},
};

/**
 * Suggest a better filename for a file (and do the
 * renaming).
 * @return the new filename
 */
char *
GNUNET_ECRS_suggest_better_filename (struct GNUNET_GE_Context *ectx,
                                     const char *filename)
{
  EXTRACTOR_ExtractorList *l;
  EXTRACTOR_KeywordList *list;
  const char *key;
  const char *mime;
  char *path;
  int i;
  unsigned int j;
  char *renameTo;
  char *ret;
  size_t max;
  struct stat filestat;

  path = GNUNET_strdup (filename);
  i = strlen (path);
  while ((i > 0) && (path[i] != DIR_SEPARATOR))
    i--;
  path[i] = '\0';
  ret = NULL;
  l = EXTRACTOR_loadDefaultLibraries ();
  list = EXTRACTOR_getKeywords (l, filename);
  key = EXTRACTOR_extractLast (EXTRACTOR_TITLE, list);
  if (key == NULL)
    key = EXTRACTOR_extractLast (EXTRACTOR_SOFTWARE, list);
  if (key == NULL)
    key = EXTRACTOR_extractLast (EXTRACTOR_DESCRIPTION, list);
  if (key == NULL)
    key = EXTRACTOR_extractLast (EXTRACTOR_COMMENT, list);
  if (key == NULL)
    key = EXTRACTOR_extractLast (EXTRACTOR_SUBJECT, list);
  if (key == NULL)
    key = EXTRACTOR_extractLast (EXTRACTOR_ALBUM, list);
  if (key == NULL)
    key = EXTRACTOR_extractLast (EXTRACTOR_UNKNOWN, list);
  mime = EXTRACTOR_extractLast (EXTRACTOR_MIMETYPE, list);
  if (mime != NULL)
    {
      i = 0;
      while ((mimeMap[i][0] != NULL) && (0 != strcmp (mime, mimeMap[i][0])))
        i++;
      if (mimeMap[i][1] == NULL)
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                       "Did not find mime type `%s' in extension list.\n",
                       mime);
      mime = mimeMap[i][1];
    }
  if (key == NULL)
    {
      key = &filename[strlen (filename) - 1];
      while ((key != filename) && (key[0] != DIR_SEPARATOR))
        key--;
      if (key[0] == DIR_SEPARATOR)
        key++;
    }
  if (mime != NULL)
    {
      if (0 == strcmp (&key[strlen (key) - strlen (mime)], mime))
        mime = NULL;
    }
  if (mime == NULL)
    {
      i = strlen (filename);
      while ((i > 0) &&
             (filename[i] != '.') && (filename[i] != DIR_SEPARATOR))
        i--;
      if (filename[i] == '.')
        mime = &filename[i];
    }
  if (mime == NULL)
    {
      max = strlen (path) + strlen (key) + strlen (DIR_SEPARATOR_STR) + 20;
      renameTo = GNUNET_malloc (max);
      GNUNET_snprintf (renameTo,
                       max,
                       "%s%s%.*s",
                       path,
                       (path[strlen (path) - 1] !=
                        DIR_SEPARATOR) ? DIR_SEPARATOR_STR : "",
                       GNUNET_MIN (255, PATH_MAX - strlen (path) - 32), key);
    }
  else
    {
      max = strlen (path) + strlen (key) + strlen (mime) +
        strlen (DIR_SEPARATOR_STR) + 20;
      renameTo = GNUNET_malloc (max);
      GNUNET_snprintf (renameTo,
                       max,
                       "%s%s%.*s%s",
                       path,
                       (path[strlen (path) - 1] !=
                        DIR_SEPARATOR) ? DIR_SEPARATOR_STR : "",
                       GNUNET_MIN (255 - strlen (mime),
                                   PATH_MAX - strlen (path) - 64), key,
                       (strcasecmp
                        (renameTo + strlen (renameTo) - strlen (mime),
                         mime) != 0) ? mime : "");


    }
  for (i = strlen (renameTo) - 1; i >= 0; i--)
    if (!isprint (renameTo[i]))
      renameTo[i] = '_';
    else if (renameTo[i] == '.' && i > 0 && renameTo[i - 1] == '.')
      {
        /* remove .. to avoid directory traversal */
        renameTo[i - 1] = renameTo[i] = '_';
        i--;
      }
  if (0 != strcmp (renameTo, filename))
    {
      if (0 == STAT (renameTo, &filestat))
        {
          i = strlen (renameTo);
          j = 0;
          do
            {
              GNUNET_snprintf (&renameTo[i], 19, ".%u", j++);
              if (j > 100000)
                break;
            }
          while (0 == STAT (renameTo, &filestat));
        }

      if (0 != STAT (renameTo, &filestat))
        {
          if (0 != RENAME (filename, renameTo))
            GNUNET_GE_LOG (ectx,
                           GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                           _("Renaming of file `%s' to `%s' failed: %s\n"),
                           filename, renameTo, STRERROR (errno));
          else
            ret = GNUNET_strdup (renameTo);
        }
      else
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("Could not rename file `%s' to `%s': file exists\n"),
                         filename, renameTo);
        }
    }
  GNUNET_free (path);
  GNUNET_free (renameTo);
  EXTRACTOR_freeKeywords (list);
  EXTRACTOR_removeAll (l);
  return ret;
}

/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 */
int
GNUNET_meta_data_test_for_directory (const struct GNUNET_MetaData *md)
{
  char *mime;
  int ret;

  mime = GNUNET_meta_data_get_by_type (md, EXTRACTOR_MIMETYPE);
  if (mime == NULL)
    return GNUNET_SYSERR;
  if (0 == strcmp (mime, GNUNET_DIRECTORY_MIME))
    ret = GNUNET_YES;
  else
    ret = GNUNET_NO;
  GNUNET_free (mime);
  return ret;
}



/* end of helper.c */

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
 * @file applications/fs/ecrs/meta.c
 * @brief Meta-data handling
 * @author Christian Grothoff
 */

#include "platform.h"
#include "ecrs.h"
#include "gnunet_ecrs_lib.h"
#include <zlib.h>

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS

/**
 * Create a fresh MetaData token.
 */
MetaData *
ECRS_createMetaData ()
{
  MetaData *ret;
  ret = MALLOC (sizeof (MetaData));
  ret->items = NULL;
  ret->itemCount = 0;
  return ret;
}

/**
 * Free meta data.
 */
void
ECRS_freeMetaData (MetaData * md)
{
  int i;
  for (i = 0; i < md->itemCount; i++)
    FREE (md->items[i].data);
  GROW (md->items, md->itemCount, 0);
  FREE (md);
}

/**
 * Add the current time as the publication date
 * to the meta-data.
 */
void
ECRS_addPublicationDateToMetaData (MetaData * md)
{
  char *dat;
  TIME_T t;

  TIME (&t);
  ECRS_delFromMetaData (md, EXTRACTOR_PUBLICATION_DATE, NULL);
  dat = GN_CTIME (&t);
  ECRS_addToMetaData (md, EXTRACTOR_PUBLICATION_DATE, dat);
  FREE (dat);
}

/**
 * Extend metadata.
 * @return OK on success, SYSERR if this entry already exists
 */
int
ECRS_addToMetaData (MetaData * md,
                    EXTRACTOR_KeywordType type, const char *data)
{
  int idx;

  GE_ASSERT (NULL, data != NULL);
  for (idx = 0; idx < md->itemCount; idx++)
    {
      if ((md->items[idx].type == type) &&
          (0 == strcmp (md->items[idx].data, data)))
        return SYSERR;
    }
  idx = md->itemCount;
  GROW (md->items, md->itemCount, md->itemCount + 1);
  md->items[idx].type = type;
  md->items[idx].data = STRDUP (data);
  return OK;
}

/**
 * Remove an item.
 * @return OK on success, SYSERR if the item does not exist in md
 */
int
ECRS_delFromMetaData (MetaData * md,
                      EXTRACTOR_KeywordType type, const char *data)
{
  int idx;
  int ret = SYSERR;
  for (idx = 0; idx < md->itemCount; idx++)
    {
      if ((md->items[idx].type == type) &&
          ((data == NULL) || (0 == strcmp (md->items[idx].data, data))))
        {
          FREE (md->items[idx].data);
          md->items[idx] = md->items[md->itemCount - 1];
          GROW (md->items, md->itemCount, md->itemCount - 1);
          if (data == NULL)
            {
              ret = OK;
              continue;
            }
          return OK;
        }
    }
  return ret;
}

/**
 * Iterate over MD entries, excluding thumbnails.
 *
 * @return number of entries
 */
int
ECRS_getMetaData (const MetaData * md,
                  ECRS_MetaDataIterator iterator, void *closure)
{
  int i;
  int sub;

  sub = 0;
  for (i = md->itemCount - 1; i >= 0; i--)
    {
      if (md->items[i].type != EXTRACTOR_THUMBNAIL_DATA)
        {
          if ((iterator != NULL) &&
              (OK != iterator (md->items[i].type,
                               md->items[i].data, closure)))
            return SYSERR;
        }
      else
        sub++;
    }
  return md->itemCount - sub;
}

/**
 * Iterate over MD entries
 *
 * @return number of entries
 */
char *
ECRS_getFromMetaData (const MetaData * md, EXTRACTOR_KeywordType type)
{
  int i;

  for (i = md->itemCount - 1; i >= 0; i--)
    if (type == md->items[i].type)
      return STRDUP (md->items[i].data);
  return NULL;
}

/**
 * Iterate over MD entries
 *
 * @return number of entries
 */
char *
ECRS_getFirstFromMetaData (const MetaData * md, ...)
{
  char *ret;
  va_list args;
  EXTRACTOR_KeywordType type;

  ret = NULL;
  va_start (args, md);
  while (1)
    {
      type = va_arg (args, EXTRACTOR_KeywordType);
      if (type == -1)
        break;
      ret = ECRS_getFromMetaData (md, type);
      if (ret != NULL)
        break;
    }
  va_end (args);
  return ret;
}


/**
 * This function can be used to decode the binary data
 * stream produced by the thumbnailextractor.
 *
 * @param in 0-terminated string from the meta-data
 * @return 1 on error, 0 on success
 */
static int
decodeThumbnail (const char *in, unsigned char **out, size_t * outSize)
{
  unsigned char *buf;
  size_t pos;
  size_t wpos;
  unsigned char marker;
  size_t i;
  size_t end;
  size_t inSize;

  inSize = strlen (in);
  if (inSize == 0)
    {
      *out = NULL;
      *outSize = 0;
      return 1;
    }

  buf = malloc (inSize);        /* slightly more than needed ;-) */
  *out = buf;

  pos = 0;
  wpos = 0;
  while (pos < inSize)
    {
      end = pos + 255;          /* 255 here: count the marker! */
      if (end > inSize)
        end = inSize;
      marker = in[pos++];
      for (i = pos; i < end; i++)
        buf[wpos++] = (in[i] == marker) ? 0 : in[i];
      pos = end;
    }
  *outSize = wpos;
  return 0;
}

/**
 * Get a thumbnail from the meta-data (if present).
 *
 * @param thumb will be set to the thumbnail data.  Must be
 *        freed by the caller!
 * @return number of bytes in thumbnail, 0 if not available
 */
size_t
ECRS_getThumbnailFromMetaData (const struct ECRS_MetaData * md,
                               unsigned char **thumb)
{
  char *encoded;
  int ret;
  size_t size;

  encoded = ECRS_getFromMetaData (md, EXTRACTOR_THUMBNAIL_DATA);
  if (encoded == NULL)
    return 0;
  if (strlen (encoded) == 0)
    {
      FREE (encoded);
      return 0;                 /* invalid */
    }
  *thumb = NULL;
  ret = decodeThumbnail (encoded, thumb, &size);
  FREE (encoded);
  if (ret == 0)
    return size;
  else
    return 0;
}

/**
 * Duplicate MetaData.
 */
MetaData *
ECRS_dupMetaData (const MetaData * md)
{
  int i;
  MetaData *ret;

  if (md == NULL)
    return NULL;
  ret = ECRS_createMetaData ();
  for (i = md->itemCount - 1; i >= 0; i--)
    ECRS_addToMetaData (ret, md->items[i].type, md->items[i].data);
  return ret;
}

/**
 * Extract meta-data from a file.
 *
 * @return SYSERR on error, otherwise the number
 *   of meta-data items obtained
 */
int
ECRS_extractMetaData (struct GE_Context *ectx,
                      MetaData * md,
                      const char *filename,
                      EXTRACTOR_ExtractorList * extractors)
{
  EXTRACTOR_KeywordList *head;
  EXTRACTOR_KeywordList *pos;
  int ret;

  if (filename == NULL)
    return SYSERR;
  if (extractors == NULL)
    return 0;
  head = EXTRACTOR_getKeywords (extractors, filename);
  head = EXTRACTOR_removeDuplicateKeywords (head,
                                            EXTRACTOR_DUPLICATES_REMOVE_UNKNOWN);
  pos = head;
  ret = 0;
  while (pos != NULL)
    {
      if (OK == ECRS_addToMetaData (md, pos->keywordType, pos->keyword))
        ret++;
      pos = pos->next;
    }
  EXTRACTOR_freeKeywords (head);
  return ret;
}

static unsigned int
tryCompression (char *data, unsigned int oldSize)
{
  char *tmp;
  uLongf dlen;

#ifdef compressBound
  dlen = compressBound (oldSize);
#else
  dlen = oldSize + (oldSize / 100) + 20;
  /* documentation says 100.1% oldSize + 12 bytes, but we
     should be able to overshoot by more to be safe */
#endif
  tmp = MALLOC (dlen);
  if (Z_OK == compress2 ((Bytef *) tmp,
                         &dlen, (const Bytef *) data, oldSize, 9))
    {
      if (dlen < oldSize)
        {
          memcpy (data, tmp, dlen);
          FREE (tmp);
          return dlen;
        }
    }
  FREE (tmp);
  return oldSize;
}

/**
 * Decompress input, return the decompressed data
 * as output, set outputSize to the number of bytes
 * that were found.
 *
 * @return NULL on error
 */
static char *
decompress (const char *input,
            unsigned int inputSize, unsigned int outputSize)
{
  char *output;
  uLongf olen;

  olen = outputSize;
  output = MALLOC (olen);
  if (Z_OK == uncompress ((Bytef *) output,
                          &olen, (const Bytef *) input, inputSize))
    {
      return output;
    }
  else
    {
      FREE (output);
      return NULL;
    }
}

/**
 * Flag in 'version' that indicates compressed meta-data.
 */
#define HEADER_COMPRESSED 0x80000000

/**
 * Bits in 'version' that give the version number.
 */
#define HEADER_VERSION_MASK 0x7FFFFFFF

typedef struct
{
  /**
   * The version of the MD serialization.
   * The highest bit is used to indicate
   * compression.
   */
  unsigned int version;

  /**
   * How many MD entries are there?
   */
  unsigned int entries;

  /**
   * Size of the MD (decompressed)
   */
  unsigned int size;

  /**
   * This is followed by 'entries' values of type 'unsigned int' that
   * correspond to EXTRACTOR_KeywordTypes.  After that, the meta-data
   * keywords follow (0-terminated).  The MD block always ends with
   * 0-termination, padding with 0 until a multiple of 8 bytes.
   */

} MetaDataHeader;

/**
 * Serialize meta-data to target.
 *
 * @param size maximum number of bytes available
 * @param part is it ok to just write SOME of the
 *        meta-data to match the size constraint,
 *        possibly discarding some data? YES/NO.
 * @return number of bytes written on success,
 *         SYSERR on error (typically: not enough
 *         space)
 */
int
ECRS_serializeMetaData (struct GE_Context *ectx,
                        const MetaData * md,
                        char *target, unsigned int max, int part)
{
  MetaDataHeader *hdr;
  size_t size;
  size_t pos;
  int i;
  int len;
  unsigned int ic;

  if (max < sizeof (MetaDataHeader))
    return SYSERR;              /* far too small */
  ic = md->itemCount;
  hdr = NULL;
  while (1)
    {
      size = sizeof (MetaDataHeader);
      size += sizeof (unsigned int) * ic;
      for (i = 0; i < ic; i++)
        size += 1 + strlen (md->items[i].data);
      while (size % 8 != 0)
        size++;
      hdr = MALLOC (size);
      hdr->version = htonl (0);
      hdr->entries = htonl (ic);
      for (i = 0; i < ic; i++)
        ((unsigned int *) &hdr[1])[i] =
          htonl ((unsigned int) md->items[i].type);
      pos = sizeof (MetaDataHeader);
      pos += sizeof (unsigned int) * ic;
      for (i = 0; i < ic; i++)
        {
          len = strlen (md->items[i].data) + 1;
          memcpy (&((char *) hdr)[pos], md->items[i].data, len);
          pos += len;
        }

      hdr->size = htonl (size);
      if ((part & ECRS_SERIALIZE_NO_COMPRESS) == 0)
        {
          pos = tryCompression ((char *) &hdr[1],
                                size - sizeof (MetaDataHeader));
        }
      else
        {
          pos = size - sizeof (MetaDataHeader);
        }
      if (pos < size - sizeof (MetaDataHeader))
        {
          hdr->version = htonl (HEADER_COMPRESSED);
          size = pos + sizeof (MetaDataHeader);
        }
      if (size <= max)
        break;
      FREE (hdr);
      hdr = NULL;

      if ((part & ECRS_SERIALIZE_PART) == 0)
        {
          return SYSERR;        /* does not fit! */
        }
      /* partial serialization ok, try again with less meta-data */
      if (size > 2 * max)
        ic = ic * 2 / 3;        /* still far too big, make big reductions */
      else
        ic--;                   /* small steps, we're close */
    }
  GE_ASSERT (ectx, size <= max);
  memcpy (target, hdr, size);
  FREE (hdr);
  /* extra check: deserialize! */
#if EXTRA_CHECKS
  {
    MetaData *mdx;
    mdx = ECRS_deserializeMetaData (ectx, target, size);
    GE_ASSERT (ectx, NULL != mdx);
    ECRS_freeMetaData (mdx);
  }
#endif
  return size;
}

/**
 * Estimate (!) the size of the meta-data in
 * serialized form.  The estimate MAY be higher
 * than what is strictly needed.
 */
unsigned int
ECRS_sizeofMetaData (const MetaData * md, int part)
{
  MetaDataHeader *hdr;
  size_t size;
  size_t pos;
  int i;
  int len;
  unsigned int ic;

  ic = md->itemCount;
  size = sizeof (MetaDataHeader);
  size += sizeof (unsigned int) * ic;
  for (i = 0; i < ic; i++)
    size += 1 + strlen (md->items[i].data);
  while (size % 8 != 0)
    size++;
  hdr = MALLOC (size);
  hdr->version = htonl (0);
  hdr->entries = htonl (md->itemCount);
  for (i = 0; i < ic; i++)
    ((unsigned int *) &hdr[1])[i] = htonl ((unsigned int) md->items[i].type);
  pos = sizeof (MetaDataHeader);
  pos += sizeof (unsigned int) * md->itemCount;
  for (i = 0; i < ic; i++)
    {
      len = strlen (md->items[i].data) + 1;
      memcpy (&((char *) hdr)[pos], md->items[i].data, len);
      pos += len;
    }
  if ((part & ECRS_SERIALIZE_NO_COMPRESS) == 0)
    {
      pos = tryCompression ((char *) &hdr[1], size - sizeof (MetaDataHeader));
    }
  else
    {
      pos = size - sizeof (MetaDataHeader);
    }
  if (pos < size - sizeof (MetaDataHeader))
    size = pos + sizeof (MetaDataHeader);

  FREE (hdr);

  return size;
}

/**
 * Deserialize meta-data.  Initializes md.
 * @param size number of bytes available
 * @return MD on success, NULL on error (i.e.
 *         bad format)
 */
struct ECRS_MetaData *
ECRS_deserializeMetaData (struct GE_Context *ectx,
                          const char *input, unsigned int size)
{
  MetaData *md;
  const MetaDataHeader *hdr;
  unsigned int ic;
  char *data;
  unsigned int dataSize;
  int compressed;
  int i;
  unsigned int pos;
  int len;

  if (size < sizeof (MetaDataHeader))
    return NULL;
  hdr = (const MetaDataHeader *) input;
  if ((ntohl (MAKE_UNALIGNED (hdr->version)) & HEADER_VERSION_MASK) != 0)
    return NULL;                /* unsupported version */
  ic = ntohl (MAKE_UNALIGNED (hdr->entries));
  compressed =
    (ntohl (MAKE_UNALIGNED (hdr->version)) & HEADER_COMPRESSED) != 0;
  if (compressed)
    {
      dataSize = ntohl (MAKE_UNALIGNED (hdr->size)) - sizeof (MetaDataHeader);
      if (dataSize > 2 * 1042 * 1024)
        {
          GE_BREAK (ectx, 0);
          return NULL;          /* only 2 MB allowed [to make sure we don't blow
                                   our memory limit because of a mal-formed
                                   message... ] */
        }
      data = decompress ((char *) &input[sizeof (MetaDataHeader)],
                         size - sizeof (MetaDataHeader), dataSize);
      if (data == NULL)
        {
          GE_BREAK (ectx, 0);
          return NULL;
        }
    }
  else
    {
      data = (char *) &hdr[1];
      dataSize = size - sizeof (MetaDataHeader);
      if (size != ntohl (MAKE_UNALIGNED (hdr->size)))
        {
          GE_BREAK (ectx, 0);
          return NULL;
        }
    }

  if ((sizeof (unsigned int) * ic + ic) > dataSize)
    {
      GE_BREAK (ectx, 0);
      goto FAILURE;
    }
  if ((ic > 0) && (data[dataSize - 1] != '\0'))
    {
      GE_BREAK (ectx, 0);
      goto FAILURE;
    }

  md = ECRS_createMetaData ();
  GROW (md->items, md->itemCount, ic);
  i = 0;
  pos = sizeof (unsigned int) * ic;
  while ((pos < dataSize) && (i < ic))
    {
      len = strlen (&data[pos]) + 1;
      md->items[i].type = (EXTRACTOR_KeywordType)
        ntohl (MAKE_UNALIGNED (((unsigned int *) data)[i]));
      md->items[i].data = STRDUP (&data[pos]);
      pos += len;
      i++;
    }
  if (i < ic)
    {                           /* oops */
      ECRS_freeMetaData (md);
      goto FAILURE;
    }
  if (compressed)
    FREE (data);
  return md;
FAILURE:
  if (compressed)
    FREE (data);
  return NULL;                  /* size too small */
}

/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 */
int
ECRS_isDirectory (const MetaData * md)
{
  int i;

  for (i = md->itemCount - 1; i >= 0; i--)
    {
      if (md->items[i].type == EXTRACTOR_MIMETYPE)
        {
          if (0 == strcmp (md->items[i].data, GNUNET_DIRECTORY_MIME))
            return YES;
          else
            return NO;
        }
    }
  return SYSERR;
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
ECRS_suggestFilename (struct GE_Context *ectx, const char *filename)
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
  struct stat filestat;

  path = STRDUP (filename);
  i = strlen (path);
  while ((i > 0) && (path[i] != DIR_SEPARATOR))
    i--;
  path[i] = '\0';
  ret = NULL;
  l = EXTRACTOR_loadDefaultLibraries ();
  list = EXTRACTOR_getKeywords (l, filename);
  key = EXTRACTOR_extractLast (EXTRACTOR_TITLE, list);
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
        GE_LOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER,
                "Did not find mime type `%s' in extension list.\n", mime);
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
        mime = STRDUP (&filename[i]);
    }
  if (mime == NULL)
    {
      renameTo =
        MALLOC (strlen (path) + strlen (key) + strlen (DIR_SEPARATOR_STR) +
                20);
      strcpy (renameTo, path);
      if (path[strlen (path) - 1] != DIR_SEPARATOR)
        strcat (renameTo, DIR_SEPARATOR_STR);
      strcat (renameTo, key);
    }
  else
    {
      renameTo =
        MALLOC (strlen (path) + strlen (key) + strlen (mime) +
                strlen (DIR_SEPARATOR_STR) + 20);
      strcpy (renameTo, path);
      if (path[strlen (path) - 1] != DIR_SEPARATOR)
        strcat (renameTo, DIR_SEPARATOR_STR);
      strcat (renameTo, key);
      if (strcasecmp (renameTo + strlen (renameTo) - strlen (mime), mime) !=
          0)
        strcat (renameTo, mime);
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
              SNPRINTF (&renameTo[i], 19, ".%u", j++);
              if (j > 100000)
                break;
            }
          while (0 == STAT (renameTo, &filestat));
        }

      if (0 != STAT (renameTo, &filestat))
        {
          if (0 != RENAME (filename, renameTo))
            GE_LOG (ectx, GE_ERROR | GE_BULK | GE_USER,
                    _("Renaming of file `%s' to `%s' failed: %s\n"),
                    filename, renameTo, STRERROR (errno));
          else
            ret = STRDUP (renameTo);
        }
      else
        {
          GE_LOG (ectx, GE_ERROR | GE_BULK | GE_USER,
                  _("Could not rename file `%s' to `%s': file exists\n"),
                  filename, renameTo);
        }
    }
  FREE (path);
  FREE (renameTo);
  EXTRACTOR_freeKeywords (list);
  EXTRACTOR_removeAll (l);
  return ret;
}

/**
 * Test if two MDs are equal.
 */
int
ECRS_equalsMetaData (const struct ECRS_MetaData *md1,
                     const struct ECRS_MetaData *md2)
{
  int i;
  int j;
  int found;

  if (md1->itemCount != md2->itemCount)
    return NO;
  for (i = 0; i < md1->itemCount; i++)
    {
      found = NO;
      for (j = 0; j < md2->itemCount; j++)
        if ((md1->items[i].type == md2->items[j].type) &&
            (0 == strcmp (md1->items[i].data, md2->items[j].data)))
          found = YES;
      if (found == NO)
        return NO;
    }
  return YES;
}


/* end of meta.c */

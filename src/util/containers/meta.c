/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file util/containers/meta.c
 * @brief Storing of meta data
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include <extractor.h>
#include <zlib.h>

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS

typedef struct
{
  EXTRACTOR_KeywordType type;
  char *data;
} Item;

/**
 * Meta data to associate with a file, directory or namespace.
 */
typedef struct GNUNET_MetaData
{
  unsigned int itemCount;
  Item *items;
} MetaData;

/**
 * Create a fresh MetaData token.
 */
MetaData *
GNUNET_meta_data_create ()
{
  MetaData *ret;
  ret = GNUNET_malloc (sizeof (MetaData));
  ret->items = NULL;
  ret->itemCount = 0;
  return ret;
}

/**
 * Free meta data.
 */
void
GNUNET_meta_data_destroy (MetaData * md)
{
  int i;

  if (md == NULL)
    return;
  for (i = 0; i < md->itemCount; i++)
    GNUNET_free (md->items[i].data);
  GNUNET_array_grow (md->items, md->itemCount, 0);
  GNUNET_free (md);
}

/**
 * Add the current time as the publication date
 * to the meta-data.
 */
void
GNUNET_meta_data_add_publication_date (MetaData * md)
{
  char *dat;
  GNUNET_Int32Time t;

  GNUNET_get_time_int32 (&t);
  GNUNET_meta_data_delete (md, EXTRACTOR_PUBLICATION_DATE, NULL);
  dat = GNUNET_int32_time_to_string (&t);
  GNUNET_meta_data_insert (md, EXTRACTOR_PUBLICATION_DATE, dat);
  GNUNET_free (dat);
}

/**
 * Extend metadata.
 * @return GNUNET_OK on success, GNUNET_SYSERR if this entry already exists
 */
int
GNUNET_meta_data_insert (MetaData * md,
                         EXTRACTOR_KeywordType type, const char *data)
{
  int idx;
  char *p;

  GNUNET_GE_ASSERT (NULL, data != NULL);
  for (idx = 0; idx < md->itemCount; idx++)
    {
      if ((md->items[idx].type == type) &&
          (0 == strcmp (md->items[idx].data, data)))
        return GNUNET_SYSERR;
    }
  idx = md->itemCount;
  GNUNET_array_grow (md->items, md->itemCount, md->itemCount + 1);
  md->items[idx].type = type;
  md->items[idx].data = p = GNUNET_strdup (data);

  /* change OS native dir separators to unix '/' and others to '_' */
  if (type == EXTRACTOR_FILENAME)
    {
      while (*p != '\0')
        {
          if (*p == DIR_SEPARATOR)
            *p = '/';
          else if (*p == '\\')
            *p = '_';
          p++;
        }
    }

  return GNUNET_OK;
}

/**
 * Remove an item.
 * @return GNUNET_OK on success, GNUNET_SYSERR if the item does not exist in md
 */
int
GNUNET_meta_data_delete (MetaData * md,
                         EXTRACTOR_KeywordType type, const char *data)
{
  int idx;
  int ret = GNUNET_SYSERR;
  for (idx = 0; idx < md->itemCount; idx++)
    {
      if ((md->items[idx].type == type) &&
          ((data == NULL) || (0 == strcmp (md->items[idx].data, data))))
        {
          GNUNET_free (md->items[idx].data);
          md->items[idx] = md->items[md->itemCount - 1];
          GNUNET_array_grow (md->items, md->itemCount, md->itemCount - 1);
          if (data == NULL)
            {
              ret = GNUNET_OK;
              continue;
            }
          return GNUNET_OK;
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
GNUNET_meta_data_get_contents (const MetaData * md,
                               GNUNET_MetaDataProcessor iterator,
                               void *closure)
{
  int i;
  int sub;

  sub = 0;
  for (i = md->itemCount - 1; i >= 0; i--)
    {
      if (!EXTRACTOR_isBinaryType (md->items[i].type))
        {
          if ((iterator != NULL) &&
              (GNUNET_OK != iterator (md->items[i].type,
                                      md->items[i].data, closure)))
            return GNUNET_SYSERR;
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
GNUNET_meta_data_get_by_type (const MetaData * md, EXTRACTOR_KeywordType type)
{
  int i;

  for (i = md->itemCount - 1; i >= 0; i--)
    if (type == md->items[i].type)
      return GNUNET_strdup (md->items[i].data);
  return NULL;
}

/**
 * Iterate over MD entries
 *
 * @return number of entries
 */
char *
GNUNET_meta_data_get_first_by_types (const MetaData * md, ...)
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
      ret = GNUNET_meta_data_get_by_type (md, type);
      if (ret != NULL)
        break;
    }
  va_end (args);
  return ret;
}

/**
 * Get a thumbnail from the meta-data (if present).
 *
 * @param thumb will be set to the thumbnail data.  Must be
 *        freed by the caller!
 * @return number of bytes in thumbnail, 0 if not available
 */
size_t
GNUNET_meta_data_get_thumbnail (const struct GNUNET_MetaData * md,
                                unsigned char **thumb)
{
  char *encoded;
  int ret;
  size_t size;

  encoded = GNUNET_meta_data_get_by_type (md, EXTRACTOR_THUMBNAIL_DATA);
  if (encoded == NULL)
    return 0;
  if (strlen (encoded) == 0)
    {
      GNUNET_free (encoded);
      return 0;                 /* invalid */
    }
  *thumb = NULL;
  ret = EXTRACTOR_binaryDecode (encoded, thumb, &size);
  GNUNET_free (encoded);
  if (ret != 0)
    return 0;
  return size;
}

/**
 * Duplicate MetaData.
 */
MetaData *
GNUNET_meta_data_duplicate (const MetaData * md)
{
  int i;
  MetaData *ret;

  if (md == NULL)
    return NULL;
  ret = GNUNET_meta_data_create ();
  for (i = md->itemCount - 1; i >= 0; i--)
    GNUNET_meta_data_insert (ret, md->items[i].type, md->items[i].data);
  return ret;
}

/**
 * Extract meta-data from a file.
 *
 * @return GNUNET_SYSERR on error, otherwise the number
 *   of meta-data items obtained
 */
int
GNUNET_meta_data_extract_from_file (struct GNUNET_GE_Context *ectx,
                                    MetaData * md,
                                    const char *filename,
                                    EXTRACTOR_ExtractorList * extractors)
{
  EXTRACTOR_KeywordList *head;
  EXTRACTOR_KeywordList *pos;
  int ret;

  if (filename == NULL)
    return GNUNET_SYSERR;
  if (extractors == NULL)
    return 0;
  head = EXTRACTOR_getKeywords (extractors, filename);
  head = EXTRACTOR_removeDuplicateKeywords (head,
                                            EXTRACTOR_DUPLICATES_REMOVE_UNKNOWN);
  pos = head;
  ret = 0;
  while (pos != NULL)
    {
      if (GNUNET_OK ==
          GNUNET_meta_data_insert (md, pos->keywordType, pos->keyword))
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
  tmp = GNUNET_malloc (dlen);
  if (Z_OK == compress2 ((Bytef *) tmp,
                         &dlen, (const Bytef *) data, oldSize, 9))
    {
      if (dlen < oldSize)
        {
          memcpy (data, tmp, dlen);
          GNUNET_free (tmp);
          return dlen;
        }
    }
  GNUNET_free (tmp);
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
  output = GNUNET_malloc (olen);
  if (Z_OK == uncompress ((Bytef *) output,
                          &olen, (const Bytef *) input, inputSize))
    {
      return output;
    }
  else
    {
      GNUNET_free (output);
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
   *
   * Version 0 is the current version;
   * Version is 1 for a NULL pointer.
   * Other version numbers are not yet defined.
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
 *        possibly discarding some data? GNUNET_YES/GNUNET_NO.
 * @return number of bytes written on success,
 *         GNUNET_SYSERR on error (typically: not enough
 *         space)
 */
int
GNUNET_meta_data_serialize (struct GNUNET_GE_Context *ectx,
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
    return GNUNET_SYSERR;       /* far too small */
  ic = md ? md->itemCount : 0;
  hdr = NULL;
  while (1)
    {
      size = sizeof (MetaDataHeader);
      size += sizeof (unsigned int) * ic;
      for (i = 0; i < ic; i++)
        size += 1 + strlen (md->items[i].data);
      while (size % 8 != 0)
        size++;
      hdr = GNUNET_malloc (size);
      hdr->version = htonl (md == NULL ? 1 : 0);
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
      if ((part & GNUNET_SERIALIZE_NO_COMPRESS) == 0)
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
      GNUNET_free (hdr);
      hdr = NULL;

      if ((part & GNUNET_SERIALIZE_PART) == 0)
        {
          return GNUNET_SYSERR; /* does not fit! */
        }
      /* partial serialization ok, try again with less meta-data */
      if (size > 2 * max)
        ic = ic * 2 / 3;        /* still far too big, make big reductions */
      else
        ic--;                   /* small steps, we're close */
    }
  GNUNET_GE_ASSERT (ectx, size <= max);
  memcpy (target, hdr, size);
  GNUNET_free (hdr);
  /* extra check: deserialize! */
#if EXTRA_CHECKS
  {
    MetaData *mdx;
    mdx = GNUNET_meta_data_deserialize (ectx, target, size);
    GNUNET_GE_ASSERT (ectx, NULL != mdx);
    GNUNET_meta_data_destroy (mdx);
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
GNUNET_meta_data_get_serialized_size (const MetaData * md, int part)
{
  MetaDataHeader *hdr;
  size_t size;
  size_t pos;
  int i;
  int len;
  unsigned int ic;

  ic = md ? md->itemCount : 0;
  size = sizeof (MetaDataHeader);
  size += sizeof (unsigned int) * ic;
  for (i = 0; i < ic; i++)
    size += 1 + strlen (md->items[i].data);
  while (size % 8 != 0)
    size++;
  hdr = GNUNET_malloc (size);
  hdr->version = htonl (md == NULL ? 1 : 0);
  hdr->entries = htonl (ic);
  for (i = 0; i < ic; i++)
    ((unsigned int *) &hdr[1])[i] = htonl ((unsigned int) md->items[i].type);
  pos = sizeof (MetaDataHeader);
  pos += sizeof (unsigned int) * ic;
  for (i = 0; i < ic; i++)
    {
      len = strlen (md->items[i].data) + 1;
      memcpy (&((char *) hdr)[pos], md->items[i].data, len);
      pos += len;
    }
  if ((part & GNUNET_SERIALIZE_NO_COMPRESS) == 0)
    {
      pos = tryCompression ((char *) &hdr[1], size - sizeof (MetaDataHeader));
    }
  else
    {
      pos = size - sizeof (MetaDataHeader);
    }
  if (pos < size - sizeof (MetaDataHeader))
    size = pos + sizeof (MetaDataHeader);
  GNUNET_free (hdr);
  return size;
}

/**
 * Deserialize meta-data.  Initializes md.
 * @param size number of bytes available
 * @return MD on success, NULL on error (i.e.
 *         bad format)
 */
struct GNUNET_MetaData *
GNUNET_meta_data_deserialize (struct GNUNET_GE_Context *ectx,
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
  unsigned int version;

  if (size < sizeof (MetaDataHeader))
    return NULL;
  hdr = (const MetaDataHeader *) input;
  version = ntohl (MAKE_UNALIGNED (hdr->version)) & HEADER_VERSION_MASK;
  if (version == 1)
    return NULL; /* null pointer */
  if (version != 0)
    {
      GNUNET_GE_BREAK_OP(NULL, 0); /* unsupported version */
      return NULL; 
    }
  ic = ntohl (MAKE_UNALIGNED (hdr->entries));
  compressed =
    (ntohl (MAKE_UNALIGNED (hdr->version)) & HEADER_COMPRESSED) != 0;
  if (compressed)
    {
      dataSize = ntohl (MAKE_UNALIGNED (hdr->size)) - sizeof (MetaDataHeader);
      if (dataSize > 2 * 1042 * 1024)
        {
          GNUNET_GE_BREAK (ectx, 0);
          return NULL;          /* only 2 MB allowed [to make sure we don't blow
                                   our memory limit because of a mal-formed
                                   message... ] */
        }
      data = decompress ((char *) &input[sizeof (MetaDataHeader)],
                         size - sizeof (MetaDataHeader), dataSize);
      if (data == NULL)
        {
          GNUNET_GE_BREAK (ectx, 0);
          return NULL;
        }
    }
  else
    {
      data = (char *) &hdr[1];
      dataSize = size - sizeof (MetaDataHeader);
      if (size != ntohl (MAKE_UNALIGNED (hdr->size)))
        {
          GNUNET_GE_BREAK (ectx, 0);
          return NULL;
        }
    }

  if ((sizeof (unsigned int) * ic + ic) > dataSize)
    {
      GNUNET_GE_BREAK (ectx, 0);
      goto FAILURE;
    }
  if ((ic > 0) && (data[dataSize - 1] != '\0'))
    {
      GNUNET_GE_BREAK (ectx, 0);
      goto FAILURE;
    }

  md = GNUNET_meta_data_create ();
  GNUNET_array_grow (md->items, md->itemCount, ic);
  i = 0;
  pos = sizeof (unsigned int) * ic;
  while ((pos < dataSize) && (i < ic))
    {
      len = strlen (&data[pos]) + 1;
      md->items[i].type = (EXTRACTOR_KeywordType)
        ntohl (MAKE_UNALIGNED (((unsigned int *) data)[i]));
      md->items[i].data = GNUNET_strdup (&data[pos]);
      pos += len;
      i++;
    }
  if (i < ic)
    {                           /* oops */
      GNUNET_meta_data_destroy (md);
      goto FAILURE;
    }
  if (compressed)
    GNUNET_free (data);
  return md;
FAILURE:
  if (compressed)
    GNUNET_free (data);
  return NULL;                  /* size too small */
}

/**
 * Test if two MDs are equal.
 */
int
GNUNET_meta_data_test_equal (const struct GNUNET_MetaData *md1,
                             const struct GNUNET_MetaData *md2)
{
  int i;
  int j;
  int found;

  if (md1->itemCount != md2->itemCount)
    return GNUNET_NO;
  for (i = 0; i < md1->itemCount; i++)
    {
      found = GNUNET_NO;
      for (j = 0; j < md2->itemCount; j++)
        if ((md1->items[i].type == md2->items[j].type) &&
            (0 == strcmp (md1->items[i].data, md2->items[j].data)))
          found = GNUNET_YES;
      if (found == GNUNET_NO)
        return GNUNET_NO;
    }
  return GNUNET_YES;
}


/* end of meta.c */

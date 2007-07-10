/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/directory.c
 * @brief Helper functions for building directories.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "ecrs.h"

/**
 * Iterate over all entries in a directory.  Note that directories
 * are structured such that it is possible to iterate over the
 * individual blocks as well as over the entire directory.  Thus
 * a client can call this function on the lastBlock in the
 * ECRS_DownloadProgressCallback.  Note that if a directory entry
 * spans multiple blocks, listDirectory may signal an error when
 * run on individual blocks even if the final directory is intact.
 * <p>
 *
 * Note that this function maybe called on parts of directories.
 * Thus parser errors should not be reported _at all_ (with BREAK).
 * Of course, returning SYSERR maybe appropriate.  Still, if some
 * entries can be recovered despite these parsing errors, the
 * function should try to do this.
 *
 * @param data pointer to the beginning of the directory
 * @param len number of bytes in data
 * @return number of entries on success, SYSERR if the
 *         directory is malformed
 */
int
ECRS_listDirectory (struct GE_Context *ectx,
                    const char *data,
                    unsigned long long len,
                    struct ECRS_MetaData **md,
                    ECRS_SearchProgressCallback spcb, void *spcbClosure)
{
  unsigned long long pos;
  unsigned long long align;
  unsigned int mdSize;
  unsigned long long epos;
  ECRS_FileInfo fi;
  int count;

  count = 0;
  *md = NULL;
  pos = 0;
  if ((len >= 8 + sizeof (unsigned int)) &&
      (0 == memcmp (data, GNUNET_DIRECTORY_MAGIC, 8)))
    {
      memcpy (&mdSize, &data[8], sizeof (unsigned int));
      mdSize = ntohl (mdSize);
      if (mdSize > len - 8 - sizeof (unsigned int))
        return SYSERR;          /* invalid size */
      *md = ECRS_deserializeMetaData (ectx,
                                      &data[8 + sizeof (unsigned int)],
                                      mdSize);
      if (*md == NULL)
        {
          GE_BREAK (ectx, 0);
          return SYSERR;        /* malformed ! */
        }
      pos = 8 + sizeof (unsigned int) + mdSize;
    }
  while (pos < len)
    {
      /* find end of URI */
      if (data[pos] == '\0')
        {
          /* URI is never empty, must be end of block,
             skip to next alignment */
          align = ((pos / BLOCK_ALIGN_SIZE) + 1) * BLOCK_ALIGN_SIZE;
          if (align == pos)
            {
              /* if we were already aligned, still skip a block! */
              align += BLOCK_ALIGN_SIZE;
            }
          pos = align;
          if (pos >= len)
            {
              /* malformed - or partial download... */
              break;
            }
        }
      epos = pos;
      while ((epos < len) && (data[epos] != '\0'))
        epos++;
      if (epos >= len)
        return SYSERR;          /* malformed - or partial download */

      fi.uri = ECRS_stringToUri (ectx, &data[pos]);
      pos = epos + 1;
      if (fi.uri == NULL)
        {
          pos--;                /* go back to '\0' to force going to next alignment */
          continue;
        }
      if (ECRS_isKeywordUri (fi.uri))
        {
          ECRS_freeUri (fi.uri);
          GE_BREAK (ectx, 0);
          return SYSERR;        /* illegal in directory! */
        }

      memcpy (&mdSize, &data[pos], sizeof (unsigned int));
      mdSize = ntohl (mdSize);

      pos += sizeof (unsigned int);
      if (pos + mdSize > len)
        {
          ECRS_freeUri (fi.uri);
          return SYSERR;        /* malformed - or partial download */
        }

      fi.meta = ECRS_deserializeMetaData (ectx, &data[pos], mdSize);
      if (fi.meta == NULL)
        {
          ECRS_freeUri (fi.uri);
          GE_BREAK (ectx, 0);
          return SYSERR;        /* malformed ! */
        }
      pos += mdSize;
      count++;
      if (spcb != NULL)
        spcb (&fi, NULL, NO, spcbClosure);
      ECRS_freeMetaData (fi.meta);
      ECRS_freeUri (fi.uri);
    }
  return count;
}

/**
 * Given the start and end position of a block of
 * data, return the end position of that data
 * after alignment to the BLOCK_ALIGN_SIZE.
 */
static unsigned long long
do_align (unsigned long long start_position, unsigned long long end_position)
{
  unsigned long long align;

  align = (end_position / BLOCK_ALIGN_SIZE) * BLOCK_ALIGN_SIZE;
  if ((start_position < align) && (end_position > align))
    return align + end_position - start_position;
  return end_position;
}

/**
 * Compute a permuation of the blocks to
 * minimize the cost of alignment.  Greedy packer.
 *
 * @param start starting position for the first block
 * @param count size of the two arrays
 * @param sizes the sizes of the individual blocks
 * @param perm the permutation of the blocks (updated)
 */
static void
block_align (unsigned long long start,
             unsigned int count, const unsigned long long *sizes, int *perm)
{
  int i;
  int j;
  int tmp;
  int best;
  long long badness;
  unsigned long long cpos;
  unsigned long long cend;
  long long cbad;
  int cval;

  cpos = start;
  for (i = 0; i < count; i++)
    {
      start = cpos;
      badness = 0x7FFFFFFF;
      best = -1;
      for (j = i; j < count; j++)
        {
          cval = perm[j];
          cend = cpos + sizes[cval];
          if (cpos % BLOCK_ALIGN_SIZE == 0)
            {
              /* prefer placing the largest blocks first */
              cbad = -(cend % BLOCK_ALIGN_SIZE);
            }
          else
            {
              if (cpos / BLOCK_ALIGN_SIZE == cend / BLOCK_ALIGN_SIZE)
                {
                  /* Data fits into the same block! Prefer small left-overs! */
                  cbad = BLOCK_ALIGN_SIZE - cend % BLOCK_ALIGN_SIZE;
                }
              else
                {
                  /* Would have to waste space to re-align, add big factor, this
                     case is a real loss (proportional to space wasted)! */
                  cbad =
                    BLOCK_ALIGN_SIZE * (BLOCK_ALIGN_SIZE -
                                        cpos % BLOCK_ALIGN_SIZE);
                }
            }
          if (cbad < badness)
            {
              best = j;
              badness = cbad;
            }
        }
      tmp = perm[i];
      perm[i] = perm[best];
      perm[best] = tmp;
      cpos += sizes[perm[i]];
      cpos = do_align (start, cpos);
    }
}

/**
 * Create a directory.  We allow packing more than one variable
 * size entry into one block (and an entry could also span more
 * than one block), but an entry that is smaller than a single
 * block will never cross the block boundary.  This is done to
 * allow processing entries of a directory already even if the
 * download is still partial.<p>
 *
 * The first block begins with the directories MAGIC signature,
 * followed by the meta-data about the directory itself.<p>
 *
 * After that, the directory consists of block-aligned pairs
 * of URIs (0-terminated strings) and serialized meta-data.
 *
 * @param data pointer set to the beginning of the directory
 * @param len set to number of bytes in data
 * @param count number of entries in uris and metaDatas
 * @param uris URIs of the files in the directory
 * @param metaDatas meta-data for the files (must match
 *        respective values at same offset in in uris)
 * @param meta meta-data for the directory.  The meta entry
 *        is extended with the mime-type for a GNUnet directory.
 * @return OK on success, SYSERR on error
 */
int
ECRS_createDirectory (struct GE_Context *ectx,
                      char **data,
                      unsigned long long *len,
                      unsigned int count,
                      const ECRS_FileInfo * fis, struct ECRS_MetaData *meta)
{
  int i;
  int j;
  unsigned long long psize;
  unsigned long long size;
  unsigned long long pos;
  char **ucs;
  int ret;
  unsigned long long *sizes;
  int *perm;

  for (i = 0; i < count; i++)
    {
      if (ECRS_isKeywordUri (fis[i].uri))
        {
          GE_BREAK (ectx, 0);
          return SYSERR;        /* illegal in directory! */
        }
    }
  ucs = MALLOC (sizeof (char *) * count);
  size = 8 + sizeof (unsigned int);
  size += ECRS_sizeofMetaData (meta, ECRS_SERIALIZE_FULL);
  sizes = MALLOC (count * sizeof (unsigned long long));
  perm = MALLOC (count * sizeof (int));
  for (i = 0; i < count; i++)
    {
      perm[i] = i;
      ucs[i] = ECRS_uriToString (fis[i].uri);
      GE_ASSERT (ectx, ucs[i] != NULL);
      psize = ECRS_sizeofMetaData (fis[i].meta, ECRS_SERIALIZE_FULL);
      if (psize == -1)
        {
          GE_BREAK (ectx, 0);
          FREE (sizes);
          FREE (perm);
          while (i >= 0)
            FREE (ucs[i--]);
          FREE (ucs);
          return SYSERR;
        }
      sizes[i] = psize + sizeof (unsigned int) + strlen (ucs[i]) + 1;
    }
  /* permutate entries to minimize alignment cost */
  block_align (size, count, sizes, perm);

  /* compute final size with alignment */
  for (i = 0; i < count; i++)
    {
      psize = size;
      size += sizes[perm[i]];
      size = do_align (psize, size);
    }
  *len = size;
  *data = MALLOC (size);
  memset (*data, 0, size);

  pos = 8;
  memcpy (*data, GNUNET_DIRECTORY_MAGIC, 8);

  ret = ECRS_serializeMetaData (ectx,
                                meta,
                                &(*data)[pos + sizeof (unsigned int)],
                                size - pos - sizeof (unsigned int),
                                ECRS_SERIALIZE_FULL);
  GE_ASSERT (ectx, ret != SYSERR);
  ret = htonl (ret);
  memcpy (&(*data)[pos], &ret, sizeof (unsigned int));
  pos += ntohl (ret) + sizeof (unsigned int);

  for (j = 0; j < count; j++)
    {
      i = perm[j];
      psize = pos;
      pos += sizes[i];
      pos = do_align (psize, pos);
      pos -= sizes[i];          /* go back to beginning */
      memcpy (&(*data)[pos], ucs[i], strlen (ucs[i]) + 1);
      pos += strlen (ucs[i]) + 1;
      FREE (ucs[i]);
      ret = ECRS_serializeMetaData (ectx,
                                    fis[i].meta,
                                    &(*data)[pos + sizeof (unsigned int)],
                                    size - pos - sizeof (unsigned int),
                                    ECRS_SERIALIZE_FULL);
      GE_ASSERT (ectx, ret != SYSERR);
      ret = htonl (ret);
      memcpy (&(*data)[pos], &ret, sizeof (unsigned int));
      pos += ntohl (ret) + sizeof (unsigned int);
    }
  FREE (sizes);
  FREE (perm);
  FREE (ucs);
  GE_ASSERT (ectx, pos == size);

  return OK;
}

/* end of directory.c */

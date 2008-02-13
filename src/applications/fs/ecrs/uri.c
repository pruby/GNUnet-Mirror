/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @brief Parses and produces uri strings.
 * @author Igor Wronsky, Christian Grothoff
 *
 * GNUnet URIs are of the general form "gnunet://MODULE/IDENTIFIER".
 * The specific structure of "IDENTIFIER" depends on the module and
 * maybe differenciated into additional subcategories if applicable.
 * This module only deals with ecrs identifiers (MODULE = "ecrs").
 * <p>
 *
 * This module only parses URIs for the AFS module.  The ECRS URIs fall
 * into four categories, "chk", "sks", "ksk" and "loc".  The first three
 * categories were named in analogy (!) to Freenet, but they do NOT
 * work in exactly the same way.  They are very similar from the user's
 * point of view (unique file identifier, subspace, keyword), but the
 * implementation is rather different in pretty much every detail.
 * The concrete URI formats are:
 *
 * <ul><li>
 *
 * First, there are URIs that identify a file.  They have the format
 * "gnunet://ecrs/chk/HEX1.HEX2.SIZE".  These URIs can be used to
 * download the file.  The description, filename, mime-type and other
 * meta-data is NOT part of the file-URI since a URI uniquely
 * identifies a resource (and the contents of the file would be the
 * same even if it had a different description).
 *
 * </li><li>
 *
 * The second category identifies entries in a namespace.  The format
 * is "gnunet://ecrs/sks/NAMESPACE/IDENTIFIER" where the namespace
 * should be given in HEX.  Applications may allow using a nickname
 * for the namespace if the nickname is not ambiguous.  The identifier
 * can be either an ASCII sequence or a HEX-encoding.  If the
 * identifier is in ASCII but the format is ambiguous and could denote
 * a HEX-string a "/" is appended to indicate ASCII encoding.
 *
 * </li> <li>
 *
 * The third category identifies ordinary searches.  The format is
 * "gnunet://ecrs/ksk/KEYWORD[+KEYWORD]*".  Using the "+" syntax
 * it is possible to encode searches with the boolean "AND" operator.
 * "+" is used since it indicates a commutative 'and' operation and
 * is unlikely to be used in a keyword by itself.
 *
 * </li><li>
 *
 * The last category identifies a datum on a specific machine.  The
 * format is "gnunet://ecrs/loc/HEX1.HEX2.SIZE.PEER.SIG.EXPTIME".  PEER is
 * the BinName of the public key of the peer storing the datum.  The
 * signature (SIG) certifies that this peer has this content.
 * HEX1, HEX2 and SIZE correspond to a 'chk' URI.
 *
 * </li></ul>
 *
 * The encoding for hexadecimal values is defined in the hashing.c
 * module (GNUNET_EncName) in the gnunet-util library and discussed there.
 * <p>
 */

#include "platform.h"
#include "ecrs.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"

/**
 * Generate a keyword URI.
 * @return NULL on error (i.e. keywordCount == 0)
 */
static char *
createKeywordURI (char **keywords, unsigned int keywordCount)
{
  size_t n;
  char *ret;
  unsigned int i;

  n =
    keywordCount + strlen (GNUNET_ECRS_URI_PREFIX) +
    strlen (GNUNET_ECRS_SEARCH_INFIX) + 1;
  for (i = 0; i < keywordCount; i++)
    n += strlen (keywords[i]);
  ret = GNUNET_malloc (n);
  strcpy (ret, GNUNET_ECRS_URI_PREFIX);
  strcat (ret, GNUNET_ECRS_SEARCH_INFIX);
  for (i = 0; i < keywordCount; i++)
    {
      strcat (ret, keywords[i]);
      if (i != keywordCount - 1)
        strcat (ret, "+");
    }
  return ret;
}

/**
 * Generate a subspace URI.
 */
static char *
createSubspaceURI (const GNUNET_HashCode * namespace,
                   const GNUNET_HashCode * identifier)
{
  size_t n;
  char *ret;
  GNUNET_EncName ns;
  GNUNET_EncName id;

  n =
    sizeof (GNUNET_EncName) * 2 + strlen (GNUNET_ECRS_URI_PREFIX) +
    strlen (GNUNET_ECRS_SUBSPACE_INFIX) + 1;
  ret = GNUNET_malloc (n);
  GNUNET_hash_to_enc (namespace, &ns);
  GNUNET_hash_to_enc (identifier, &id);
  GNUNET_snprintf (ret, n,
                   "%s%s%s/%s",
                   GNUNET_ECRS_URI_PREFIX, GNUNET_ECRS_SUBSPACE_INFIX,
                   (char *) &ns, (char *) &id);
  return ret;
}

/**
 * Generate a file URI.
 */
static char *
createFileURI (const FileIdentifier * fi)
{
  char *ret;
  GNUNET_EncName keyhash;
  GNUNET_EncName queryhash;
  size_t n;

  GNUNET_hash_to_enc (&fi->chk.key, &keyhash);
  GNUNET_hash_to_enc (&fi->chk.query, &queryhash);

  n =
    strlen (GNUNET_ECRS_URI_PREFIX) + 2 * sizeof (GNUNET_EncName) + 8 + 16 +
    32 + strlen (GNUNET_ECRS_FILE_INFIX);
  ret = GNUNET_malloc (n);
  GNUNET_snprintf (ret,
                   n,
                   "%s%s%s.%s.%llu",
                   GNUNET_ECRS_URI_PREFIX,
                   GNUNET_ECRS_FILE_INFIX,
                   (char *) &keyhash, (char *) &queryhash,
                   GNUNET_ntohll (fi->file_length));
  return ret;
}

#include "bincoder.c"

/**
 * Create a (string) location URI from a Location.
 */
static char *
createLocURI (const Location * loc)
{
  size_t n;
  char *ret;
  GNUNET_EncName keyhash;
  GNUNET_EncName queryhash;
  char *peerId;
  char *peerSig;

  GNUNET_hash_to_enc (&loc->fi.chk.key, &keyhash);
  GNUNET_hash_to_enc (&loc->fi.chk.query, &queryhash);
  n = 2148;
  peerId = bin2enc (&loc->peer, sizeof (GNUNET_RSA_PublicKey));
  peerSig = bin2enc (&loc->contentSignature, sizeof (GNUNET_RSA_Signature));
  ret = GNUNET_malloc (n);
  GNUNET_snprintf (ret,
                   n,
                   "%s%s%s.%s.%llu.%s.%s.%u",
                   GNUNET_ECRS_URI_PREFIX,
                   GNUNET_ECRS_LOCATION_INFIX,
                   (char *) &keyhash,
                   (char *) &queryhash,
                   GNUNET_ntohll (loc->fi.file_length),
                   peerId, peerSig, loc->expirationTime);
  GNUNET_free (peerSig);
  GNUNET_free (peerId);
  return ret;
}

/**
 * Convert a URI to a UTF-8 String.
 */
char *
GNUNET_ECRS_uri_to_string (const struct GNUNET_ECRS_URI *uri)
{
  if (uri == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return NULL;
    }
  switch (uri->type)
    {
    case ksk:
      return createKeywordURI (uri->data.ksk.keywords,
                               uri->data.ksk.keywordCount);
    case sks:
      return createSubspaceURI (&uri->data.sks.namespace,
                                &uri->data.sks.identifier);
    case chk:
      return createFileURI (&uri->data.fi);
    case loc:
      return createLocURI (&uri->data.loc);
    default:
      GNUNET_GE_BREAK (NULL, 0);
      return NULL;
    }
}

/**
 * Parses an AFS search URI.
 *
 * @param uri an uri string
 * @param keyword will be set to an array with the keywords
 * @return GNUNET_SYSERR if this is not a search URI, otherwise
 *  the number of keywords placed in the array
 */
static int
parseKeywordURI (struct GNUNET_GE_Context *ectx, const char *uri,
                 char ***keywords)
{
  unsigned int pos;
  int ret;
  int iret;
  int i;
  size_t slen;
  char *dup;

  GNUNET_GE_ASSERT (ectx, uri != NULL);

  slen = strlen (uri);
  pos = strlen (GNUNET_ECRS_URI_PREFIX);

  if (0 != strncmp (uri, GNUNET_ECRS_URI_PREFIX, pos))
    return GNUNET_SYSERR;
  if (0 !=
      strncmp (&uri[pos], GNUNET_ECRS_SEARCH_INFIX,
               strlen (GNUNET_ECRS_SEARCH_INFIX)))
    return GNUNET_SYSERR;
  pos += strlen (GNUNET_ECRS_SEARCH_INFIX);
  if (slen == pos)
    {
      /* no keywords */
      (*keywords) = NULL;
      return 0;
    }
  if ((uri[slen - 1] == '+') || (uri[pos] == '+'))
    return GNUNET_SYSERR;       /* no keywords / malformed */

  ret = 1;
  for (i = pos; i < slen; i++)
    {
      if (uri[i] == '+')
        {
          ret++;
          if (uri[i - 1] == '+')
            return GNUNET_SYSERR;       /* "++" not allowed */
        }
    }
  iret = ret;
  dup = GNUNET_strdup (uri);
  (*keywords) = GNUNET_malloc (ret * sizeof (char *));
  for (i = slen - 1; i >= pos; i--)
    {
      if (dup[i] == '+')
        {
          (*keywords)[--ret] = GNUNET_strdup (&dup[i + 1]);
          dup[i] = '\0';
        }
    }
  (*keywords)[--ret] = GNUNET_strdup (&dup[pos]);
  GNUNET_GE_ASSERT (ectx, ret == 0);
  GNUNET_free (dup);
  return iret;
}

/**
 * Parses an AFS namespace / subspace identifier URI.
 *
 * @param uri an uri string
 * @param namespace set to the namespace ID
 * @param identifier set to the ID in the namespace
 * @return GNUNET_OK on success, GNUNET_SYSERR if this is not a namespace URI
 */
static int
parseSubspaceURI (struct GNUNET_GE_Context *ectx,
                  const char *uri,
                  GNUNET_HashCode * namespace, GNUNET_HashCode * identifier)
{
  unsigned int pos;
  size_t slen;
  char *up;

  GNUNET_GE_ASSERT (ectx, uri != NULL);

  slen = strlen (uri);
  pos = strlen (GNUNET_ECRS_URI_PREFIX);

  if (0 != strncmp (uri, GNUNET_ECRS_URI_PREFIX, pos))
    return GNUNET_SYSERR;
  if (0 != strncmp (&uri[pos],
                    GNUNET_ECRS_SUBSPACE_INFIX,
                    strlen (GNUNET_ECRS_SUBSPACE_INFIX)))
    return GNUNET_SYSERR;
  pos += strlen (GNUNET_ECRS_SUBSPACE_INFIX);
  if ((slen < pos + sizeof (GNUNET_EncName) + 1) ||
      (!((uri[pos + sizeof (GNUNET_EncName) - 1] == '/') ||
         (uri[pos + sizeof (GNUNET_EncName) - 1] == '\\'))))
    return GNUNET_SYSERR;

  up = GNUNET_strdup (uri);
  up[pos + sizeof (GNUNET_EncName) - 1] = '\0';
  if ((GNUNET_OK != GNUNET_enc_to_hash (&up[pos], namespace)))
    {
      GNUNET_free (up);
      return GNUNET_SYSERR;
    }
  if ((slen != pos + 2 * sizeof (GNUNET_EncName) - 1) ||
      (GNUNET_OK !=
       GNUNET_enc_to_hash (&up[pos + sizeof (GNUNET_EncName)], identifier)))
    {
      if (up[slen - 1] == '\\')
        up[--slen] = '\0';
      GNUNET_hash (&up[pos + sizeof (GNUNET_EncName)],
                   slen - (pos + sizeof (GNUNET_EncName)), identifier);
    }
  GNUNET_free (up);
  return GNUNET_OK;
}

/**
 * Parses an URI that identifies a file
 *
 * @param uri an uri string
 * @param fi the file identifier
 * @return GNUNET_OK on success, GNUNET_SYSERR if this is not a file URI
 */
static int
parseFileURI (struct GNUNET_GE_Context *ectx, const char *uri,
              FileIdentifier * fi)
{
  unsigned int pos;
  size_t slen;
  char *dup;

  GNUNET_GE_ASSERT (ectx, uri != NULL);

  slen = strlen (uri);
  pos = strlen (GNUNET_ECRS_URI_PREFIX);

  if (0 != strncmp (uri, GNUNET_ECRS_URI_PREFIX, pos))
    return GNUNET_SYSERR;
  if (0 !=
      strncmp (&uri[pos], GNUNET_ECRS_FILE_INFIX,
               strlen (GNUNET_ECRS_FILE_INFIX)))
    return GNUNET_SYSERR;
  pos += strlen (GNUNET_ECRS_FILE_INFIX);
  if ((slen < pos + 2 * sizeof (GNUNET_EncName) + 1) ||
      (uri[pos + sizeof (GNUNET_EncName) - 1] != '.') ||
      (uri[pos + sizeof (GNUNET_EncName) * 2 - 1] != '.'))
    return GNUNET_SYSERR;

  dup = GNUNET_strdup (uri);
  dup[pos + sizeof (GNUNET_EncName) - 1] = '\0';
  dup[pos + sizeof (GNUNET_EncName) * 2 - 1] = '\0';
  if ((GNUNET_OK != GNUNET_enc_to_hash (&dup[pos],
                                        &fi->chk.key)) ||
      (GNUNET_OK != GNUNET_enc_to_hash (&dup[pos + sizeof (GNUNET_EncName)],
                                        &fi->chk.query)) ||
      (1 != SSCANF (&dup[pos + sizeof (GNUNET_EncName) * 2],
                    "%llu", &fi->file_length)))
    {
      GNUNET_free (dup);
      return GNUNET_SYSERR;
    }
  GNUNET_free (dup);
  fi->file_length = GNUNET_htonll (fi->file_length);
  return GNUNET_OK;
}

/**
 * Parses an URI that identifies a location (and file).
 * Also verifies validity of the location URI.
 *
 * @param uri an uri string
 * @param loc where to store the location
 * @return GNUNET_OK on success, GNUNET_SYSERR if this is not a file URI
 */
static int
parseLocationURI (struct GNUNET_GE_Context *ectx, const char *uri,
                  Location * loc)
{
  unsigned int pos;
  unsigned int npos;
  int ret;
  size_t slen;
  char *dup;
  char *addr;


  GNUNET_GE_ASSERT (ectx, uri != NULL);
  addr = NULL;
  slen = strlen (uri);
  pos = strlen (GNUNET_ECRS_URI_PREFIX);

  if (0 != strncmp (uri, GNUNET_ECRS_URI_PREFIX, pos))
    return GNUNET_SYSERR;
  if (0 != strncmp (&uri[pos],
                    GNUNET_ECRS_LOCATION_INFIX,
                    strlen (GNUNET_ECRS_LOCATION_INFIX)))
    return GNUNET_SYSERR;
  pos += strlen (GNUNET_ECRS_LOCATION_INFIX);
  if ((slen < pos + 2 * sizeof (GNUNET_EncName) + 1) ||
      (uri[pos + sizeof (GNUNET_EncName) - 1] != '.') ||
      (uri[pos + sizeof (GNUNET_EncName) * 2 - 1] != '.'))
    return GNUNET_SYSERR;

  dup = GNUNET_strdup (uri);
  dup[pos + sizeof (GNUNET_EncName) - 1] = '\0';
  dup[pos + sizeof (GNUNET_EncName) * 2 - 1] = '\0';
  npos = pos + sizeof (GNUNET_EncName) * 2;
  while ((uri[npos] != '\0') && (uri[npos] != '.'))
    npos++;
  if (dup[npos] == '\0')
    goto ERR;
  dup[npos++] = '\0';
  if ((GNUNET_OK != GNUNET_enc_to_hash (&dup[pos],
                                        &loc->fi.chk.key)) ||
      (GNUNET_OK != GNUNET_enc_to_hash (&dup[pos + sizeof (GNUNET_EncName)],
                                        &loc->fi.chk.query)) ||
      (1 != SSCANF (&dup[pos + sizeof (GNUNET_EncName) * 2],
                    "%llu", &loc->fi.file_length)))
    goto ERR;
  loc->fi.file_length = GNUNET_htonll (loc->fi.file_length);
  ret = enc2bin (&dup[npos], &loc->peer, sizeof (GNUNET_RSA_PublicKey));
  if (ret == -1)
    goto ERR;
  npos += ret;
  if (dup[npos++] != '.')
    goto ERR;
  ret =
    enc2bin (&dup[npos], &loc->contentSignature,
             sizeof (GNUNET_RSA_Signature));
  if (ret == -1)
    goto ERR;
  npos += ret;
  if (dup[npos++] != '.')
    goto ERR;
  if (1 != SSCANF (&dup[npos], "%u", &loc->expirationTime))
    goto ERR;
  /* Finally: verify sigs! */
  if (GNUNET_OK != GNUNET_RSA_verify (&loc->fi,
                                      sizeof (FileIdentifier) +
                                      sizeof (GNUNET_PeerIdentity) +
                                      sizeof (GNUNET_Int32Time),
                                      &loc->contentSignature, &loc->peer))
    goto ERR;
  GNUNET_free (dup);
  return GNUNET_OK;
ERR:
  GNUNET_free (dup);
  GNUNET_free_non_null (addr);
  return GNUNET_SYSERR;
}

/**
 * Convert a UTF-8 String to a URI.
 */
URI *
GNUNET_ECRS_string_to_uri (struct GNUNET_GE_Context * ectx, const char *uri)
{
  URI *ret;
  int len;

  ret = GNUNET_malloc (sizeof (URI));
  if (GNUNET_OK == parseFileURI (ectx, uri, &ret->data.fi))
    {
      ret->type = chk;
      return ret;
    }
  if (GNUNET_OK == parseSubspaceURI (ectx,
                                     uri,
                                     &ret->data.sks.namespace,
                                     &ret->data.sks.identifier))
    {
      ret->type = sks;
      return ret;
    }
  if (GNUNET_OK == parseLocationURI (ectx, uri, &ret->data.loc))
    {
      ret->type = loc;
      return ret;
    }
  len = parseKeywordURI (ectx, uri, &ret->data.ksk.keywords);
  if (len < 0)
    {
      GNUNET_free (ret);
      return NULL;
    }
  ret->type = ksk;
  ret->data.ksk.keywordCount = len;
  return ret;
}

/**
 * Free URI.
 */
void
GNUNET_ECRS_uri_destroy (struct GNUNET_ECRS_URI *uri)
{
  int i;

  GNUNET_GE_ASSERT (NULL, uri != NULL);
  switch (uri->type)
    {
    case ksk:
      for (i = 0; i < uri->data.ksk.keywordCount; i++)
        GNUNET_free (uri->data.ksk.keywords[i]);
      GNUNET_array_grow (uri->data.ksk.keywords, uri->data.ksk.keywordCount,
                         0);
      break;
    case loc:
      break;
    default:
      /* do nothing */
      break;
    }
  GNUNET_free (uri);
}

/**
 * Is this a namespace URI?
 */
int
GNUNET_ECRS_uri_test_sks (const struct GNUNET_ECRS_URI *uri)
{
  return uri->type == sks;
}

/**
 * Get the (globally unique) name for the given namespace.
 *
 * @return the name (GNUNET_hash) of the namespace, caller
 *  must free it.
 */
char *
GNUNET_ECRS_get_namespace_name (const GNUNET_HashCode * id)
{
  char *ret;

  ret = GNUNET_malloc (sizeof (GNUNET_EncName));
  GNUNET_hash_to_enc (id, (GNUNET_EncName *) ret);
  return ret;
}

/**
 * Get the (globally unique) ID of the namespace
 * from the given namespace URI.
 *
 * @return GNUNET_OK on success
 */
int
GNUNET_ECRS_uri_get_namespace_from_sks (const struct GNUNET_ECRS_URI *uri,
                                        GNUNET_HashCode * id)
{
  if (!GNUNET_ECRS_uri_test_sks (uri))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  *id = uri->data.sks.namespace;
  return GNUNET_OK;
}

/**
 * Get the content ID of an SKS URI.
 *
 * @return GNUNET_OK on success
 */
int
GNUNET_ECRS_uri_get_content_hash_from_sks (const struct GNUNET_ECRS_URI *uri,
                                           GNUNET_HashCode * id)
{
  if (!GNUNET_ECRS_uri_test_sks (uri))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  *id = uri->data.sks.identifier;
  return GNUNET_OK;
}

/**
 * Is this a keyword URI?
 */
int
GNUNET_ECRS_uri_test_ksk (const struct GNUNET_ECRS_URI *uri)
{
#if EXTRA_CHECKS
  int i;

  if (uri->type == ksk)
    {
      for (i = uri->data.ksk.keywordCount - 1; i >= 0; i--)
        GNUNET_GE_ASSERT (NULL, uri->data.ksk.keywords[i] != NULL);
    }
#endif
  return uri->type == ksk;
}


/**
 * How many keywords are ANDed in this keyword URI?
 * @return 0 if this is not a keyword URI
 */
unsigned int
GNUNET_ECRS_uri_get_keyword_count_from_ksk (const struct GNUNET_ECRS_URI *uri)
{
  if (uri->type != ksk)
    return 0;
  return uri->data.ksk.keywordCount;
}

/**
 * Iterate over all keywords in this keyword URI?
 * @return -1 if this is not a keyword URI, otherwise number of
 *   keywords iterated over until iterator aborted
 */
int
GNUNET_ECRS_uri_get_keywords_from_ksk (const struct GNUNET_ECRS_URI *uri,
                                       GNUNET_ECRS_KeywordIterator iterator,
                                       void *cls)
{
  int i;
  if (uri->type != ksk)
    {
      return -1;
    }
  else
    {
      for (i = 0; i < uri->data.ksk.keywordCount; i++)
        if (iterator != NULL)
          if (GNUNET_OK != iterator (uri->data.ksk.keywords[i], cls))
            return i;
      return i;
    }
}


/**
 * Is this a file (or directory) URI?
 */
int
GNUNET_ECRS_uri_test_chk (const struct GNUNET_ECRS_URI *uri)
{
  return uri->type == chk;
}

/**
 * Is this a location URI? (DHT specific!)
 */
int
GNUNET_ECRS_uri_test_loc (const struct GNUNET_ECRS_URI *uri)
{
  return uri->type == loc;
}


/**
 * What is the size of the file that this URI
 * refers to?
 */
unsigned long long
GNUNET_ECRS_uri_get_file_size (const struct GNUNET_ECRS_URI *uri)
{
  switch (uri->type)
    {
    case chk:
      return GNUNET_ntohll (uri->data.fi.file_length);
    case loc:
      return GNUNET_ntohll (uri->data.loc.fi.file_length);
    default:
      GNUNET_GE_ASSERT (NULL, 0);
    }
  return 0;                     /* unreachable */
}


/**
 * Duplicate URI.
 */
URI *
GNUNET_ECRS_uri_duplicate (const URI * uri)
{
  struct GNUNET_ECRS_URI *ret;
  int i;

  ret = GNUNET_malloc (sizeof (URI));
  memcpy (ret, uri, sizeof (URI));
  switch (ret->type)
    {
    case ksk:
      if (ret->data.ksk.keywordCount > 0)
        {
          ret->data.ksk.keywords
            = GNUNET_malloc (ret->data.ksk.keywordCount * sizeof (char *));
          for (i = 0; i < ret->data.ksk.keywordCount; i++)
            ret->data.ksk.keywords[i] =
              GNUNET_strdup (uri->data.ksk.keywords[i]);
        }
      break;
    case loc:
      break;
    default:
      break;
    }
  return ret;
}

/**
 * Expand a keyword-URI by duplicating all keywords,
 * adding the current date (YYYY-MM-DD) after each
 * keyword.
 */
URI *
GNUNET_ECRS_uri_expand_keywords_with_date (const URI * uri)
{
  URI *ret;
  int i;
  char *key;
  char *kd;
  struct tm t;
  time_t now;
  unsigned int keywordCount;

  GNUNET_GE_ASSERT (NULL, uri->type == ksk);
  time (&now);
#ifdef HAVE_GMTIME_R
  gmtime_r (&now, &t);
#else
  t = *gmtime (&now);
#endif

  ret = GNUNET_malloc (sizeof (URI));
  ret->type = ksk;
  keywordCount = uri->data.ksk.keywordCount;
  ret->data.ksk.keywordCount = 2 * keywordCount;
  if (keywordCount > 0)
    {
      ret->data.ksk.keywords =
        GNUNET_malloc (sizeof (char *) * keywordCount * 2);
      for (i = 0; i < keywordCount; i++)
        {
          key = uri->data.ksk.keywords[i];
          GNUNET_GE_ASSERT (NULL, key != NULL);
          ret->data.ksk.keywords[2 * i] = GNUNET_strdup (key);
          kd = GNUNET_malloc (strlen (key) + 13);
          memset (kd, 0, strlen (key) + 13);
          strcpy (kd, key);
          strftime (&kd[strlen (key)], 13, "-%Y-%m-%d", &t);
          ret->data.ksk.keywords[2 * i + 1] = kd;
        }
    }
  else
    ret->data.ksk.keywords = NULL;

  return ret;
}


/**
 * Construct a keyword-URI from meta-data (take all entries
 * in the meta-data and construct one large keyword URI
 * that lists all keywords that can be found in the meta-data).
 */
URI *
GNUNET_ECRS_meta_data_to_uri (const MetaData * md)
{
  URI *ret;
  int i;
  int j;
  int havePreview;
  int add;

  if (md == NULL)
    return NULL;
  ret = GNUNET_malloc (sizeof (URI));
  ret->type = ksk;
  ret->data.ksk.keywordCount = 0;
  ret->data.ksk.keywords = NULL;
  havePreview = 0;
  for (i = md->itemCount - 1; i >= 0; i--)
    {
      if (md->items[i].type == EXTRACTOR_THUMBNAIL_DATA)
        {
          havePreview++;
        }
      else
        {
          for (j = md->itemCount - 1; j > i; j--)
            {
              if (0 == strcmp (md->items[i].data, md->items[j].data))
                {
                  havePreview++;        /* duplicate! */
                  break;
                }
            }
        }
    }
  GNUNET_array_grow (ret->data.ksk.keywords,
                     ret->data.ksk.keywordCount, md->itemCount - havePreview);
  for (i = md->itemCount - 1; i >= 0; i--)
    {
      if (md->items[i].type == EXTRACTOR_THUMBNAIL_DATA)
        {
          havePreview--;
        }
      else
        {
          add = 1;
          for (j = md->itemCount - 1; j > i; j--)
            {
              if (0 == strcmp (md->items[i].data, md->items[j].data))
                {
                  havePreview--;
                  add = 0;
                  break;
                }
            }
          if (add == 1)
            {
              GNUNET_GE_ASSERT (NULL, md->items[i].data != NULL);
              ret->data.ksk.keywords[i - havePreview]
                = GNUNET_strdup (md->items[i].data);
            }
        }
    }
  return ret;
}

/**
 * Convert a NULL-terminated array of keywords
 * to an ECRS URI.
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_keyword_strings_to_uri (const char *keyword[])
{
  unsigned int count;
  URI *ret;
  unsigned int i;

  count = 0;
  while (keyword[count] != NULL)
    count++;

  ret = GNUNET_malloc (sizeof (URI));
  ret->type = ksk;
  ret->data.ksk.keywordCount = 0;
  ret->data.ksk.keywords = NULL;
  GNUNET_array_grow (ret->data.ksk.keywords, ret->data.ksk.keywordCount,
                     count);
  for (i = 0; i < count; i++)
    ret->data.ksk.keywords[i] = GNUNET_strdup (keyword[i]);
  return ret;
}



/**
 * Are these two URIs equal?
 */
int
GNUNET_ECRS_uri_test_equal (const struct GNUNET_ECRS_URI *uri1,
                            const struct GNUNET_ECRS_URI *uri2)
{
  int ret;
  int i;
  int j;

  GNUNET_GE_ASSERT (NULL, uri1 != NULL);
  GNUNET_GE_ASSERT (NULL, uri2 != NULL);
  if (uri1->type != uri2->type)
    return GNUNET_NO;
  switch (uri1->type)
    {
    case chk:
      if (0 == memcmp (&uri1->data.fi,
                       &uri2->data.fi, sizeof (FileIdentifier)))
        return GNUNET_YES;
      return GNUNET_NO;
    case sks:
      if ((0 == memcmp (&uri1->data.sks.namespace,
                        &uri2->data.sks.namespace,
                        sizeof (GNUNET_HashCode))) &&
          (0 == memcmp (&uri1->data.sks.identifier,
                        &uri2->data.sks.identifier,
                        sizeof (GNUNET_HashCode))))

        return GNUNET_YES;
      return GNUNET_NO;
    case ksk:
      if (uri1->data.ksk.keywordCount != uri2->data.ksk.keywordCount)
        return GNUNET_NO;
      for (i = 0; i < uri1->data.ksk.keywordCount; i++)
        {
          ret = GNUNET_NO;
          for (j = 0; j < uri2->data.ksk.keywordCount; j++)
            {
              if (0 == strcmp (uri1->data.ksk.keywords[i],
                               uri2->data.ksk.keywords[j]))
                {
                  ret = GNUNET_YES;
                  break;
                }
            }
          if (ret == GNUNET_NO)
            return GNUNET_NO;
        }
      return GNUNET_YES;
    case loc:
      if (memcmp (&uri1->data.loc,
                  &uri2->data.loc,
                  sizeof (FileIdentifier) +
                  sizeof (GNUNET_RSA_PublicKey) +
                  sizeof (GNUNET_Int32Time) +
                  sizeof (unsigned short) + sizeof (unsigned short)) != 0)
        return GNUNET_NO;
      return GNUNET_YES;
    default:
      return GNUNET_NO;
    }
}

/**
 * Obtain the identity of the peer offering the data
 * @return -1 if this is not a location URI, otherwise GNUNET_OK
 */
int
GNUNET_ECRS_uri_get_peer_identity_from_loc (const struct GNUNET_ECRS_URI *uri,
                                            GNUNET_PeerIdentity * peer)
{
  if (uri->type != loc)
    return -1;
  GNUNET_hash (&uri->data.loc.peer, sizeof (GNUNET_RSA_PublicKey),
               &peer->hashPubKey);
  return GNUNET_OK;
}

/**
 * Obtain the URI of the content itself.
 *
 * @return NULL if argument is not a location URI
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_uri_get_content_uri_from_loc (const struct GNUNET_ECRS_URI *uri)
{
  struct GNUNET_ECRS_URI *ret;

  if (uri->type != loc)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_ECRS_URI));
  ret->type = chk;
  ret->data.fi = uri->data.loc.fi;
  return ret;
}

/**
 * Construct a location URI.
 *
 * @param baseURI content offered by the sender
 * @param sender identity of the peer with the content
 * @param expirationTime how long will the content be offered?
 * @param proto transport protocol to reach the peer
 * @param sas sender address size (for HELLO)
 * @param address sas bytes of address information
 * @param signer function to call for obtaining
 *        RSA signatures for "sender".
 * @return the location URI
 */
struct GNUNET_ECRS_URI *
GNUNET_ECRS_location_to_uri (const struct GNUNET_ECRS_URI *baseUri,
                             const GNUNET_RSA_PublicKey * sender,
                             GNUNET_Int32Time expirationTime,
                             GNUNET_ECRS_SignFunction signer,
                             void *signer_cls)
{
  struct GNUNET_ECRS_URI *uri;

  if (baseUri->type != chk)
    return NULL;

  uri = GNUNET_malloc (sizeof (struct GNUNET_ECRS_URI));
  uri->type = loc;
  uri->data.loc.fi = baseUri->data.fi;
  uri->data.loc.peer = *sender;
  uri->data.loc.expirationTime = expirationTime;
  signer (signer_cls,
          sizeof (FileIdentifier) +
          sizeof (GNUNET_PeerIdentity) +
          sizeof (GNUNET_Int32Time),
          &uri->data.loc.fi, &uri->data.loc.contentSignature);
  return uri;
}


/* end of uri.c */

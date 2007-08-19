/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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

     Based on http://www.pomakis.com/hashtable/hashtable.c which is public
     domain
*/

/**
 * @brief Hashtable implementation
 * @author Keith Pomakis
 * @author Nils Durner
 * @file util/hashtable.c
 */

#include "gnunet_util.h"
#include "gnunet_util_containers.h"
#include "platform.h"

typedef struct KeyValuePair
{
  void *key;
  unsigned long keylen;
  void *value;
  unsigned long valuelen;
  struct KeyValuePair *next;
} KeyValuePair;

typedef struct HashTable
{
  long numOfBuckets;
  long numOfElements;
  KeyValuePair **bucketArray;
  float idealRatio;
  float lowerRehashThreshold;
  float upperRehashThreshold;
} HashTable;

/**
 * @brief Create a cryptographically weak hashcode from a buffer
 * @param z the buffer to hash
 * @param n the size of z
 * @return the hashcode
 */
static unsigned long long
weakHash (const char *z, int n)
{
  unsigned long long h = 0;
  while (n > 0)
    {
      h = (h << 3) ^ h ^ (unsigned char) *z++;
      n--;
    }
  return h;
}


static int
isProbablePrime (long oddNumber)
{
  long i;

  for (i = 3; i < 51; i += 2)
    if (oddNumber == i)
      return 1;
    else if (oddNumber % i == 0)
      return 0;

  return 1;                     /* maybe */
}

static long
calculateIdealNumOfBuckets (const struct HashTable *hashTable)
{
  long idealNumOfBuckets = hashTable->numOfElements / hashTable->idealRatio;
  if (idealNumOfBuckets < 5)
    idealNumOfBuckets = 5;
  else
    idealNumOfBuckets |= 0x01;  /* make it an odd number */
  while (!isProbablePrime (idealNumOfBuckets))
    idealNumOfBuckets += 2;

  return idealNumOfBuckets;
}


/**
 * @brief creates a new HashTable
 * @param numOfBuckets the number of buckets to start the HashTable out with.
 *                     Must be greater than zero, and should be prime.
 *                     Ideally, the number of buckets should between 1/5
 *                     and 1 times the expected number of elements in the
 *                     HashTable.  Values much more or less than this will
 *                     result in wasted memory or decreased performance
 *                     respectively.  The number of buckets in a HashTable
 *                     can be re-calculated to an appropriate number by
 *                     calling the HashTableRehash() function once the
 *                     HashTable has been populated.  The number of buckets
 *                     in a HashTable may also be re-calculated
 *                     automatically if the ratio of elements to buckets
 *                     passes the thresholds set by ht_setIdealRatio().
 * @return a new Hashtable, or NULL on error
 */
struct HashTable *
ht_create (long numOfBuckets)
{
  struct HashTable *hashTable;
  int i;

  if (numOfBuckets <= 0)
    return NULL;

  hashTable = (struct HashTable *) MALLOC (sizeof (struct HashTable));
  if (hashTable == NULL)
    return NULL;

  hashTable->bucketArray = (KeyValuePair **)
    MALLOC (numOfBuckets * sizeof (KeyValuePair *));
  if (hashTable->bucketArray == NULL)
    {
      FREE (hashTable);
      return NULL;
    }

  hashTable->numOfBuckets = numOfBuckets;
  hashTable->numOfElements = 0;

  for (i = 0; i < numOfBuckets; i++)
    hashTable->bucketArray[i] = NULL;

  hashTable->idealRatio = 3.0;
  hashTable->lowerRehashThreshold = 0.0;
  hashTable->upperRehashThreshold = 15.0;

  return hashTable;
}

/**
 * @brief destroys an existing HashTable
 * @param hashTable the HashTable to destroy
 */
void
ht_destroy (struct HashTable *hashTable)
{
  int i;

  for (i = 0; i < hashTable->numOfBuckets; i++)
    {
      KeyValuePair *pair = hashTable->bucketArray[i];
      while (pair != NULL)
        {
          KeyValuePair *nextPair = pair->next;
          FREE (pair->key);
          FREE (pair->value);
          FREE (pair);
          pair = nextPair;
        }
    }

  FREE (hashTable->bucketArray);
  FREE (hashTable);
}

/**
 * @brief checks the existence of a key in a HashTable
 * @param hashTable the HashTable to search
 * @param key the key to search for
 * @return whether or not the specified HashTable contains the
 *         specified key
 */
int
ht_containsKey (const struct HashTable *hashTable,
                const void *key, const unsigned int keylen)
{
  void *ret;
  unsigned int retlen;

  return ht_get (hashTable, key, keylen, &ret, &retlen);
}

/**
 * @brief checks the existence of a value in a HashTable
 * @param hashTable the HashTable to search
 * @param value the value to search for
 * @return whether or not the specified HashTable contains the
 *         specified value
 */
int
ht_containsValue (const struct HashTable *hashTable,
                  const void *value, const unsigned int valuelen)
{
  int i;

  for (i = 0; i < hashTable->numOfBuckets; i++)
    {
      KeyValuePair *pair = hashTable->bucketArray[i];
      while (pair != NULL)
        {
          if ((pair->valuelen == valuelen) &&
              (memcmp (value, pair->value, valuelen) == 0))
            return 1;
          pair = pair->next;
        }
    }

  return 0;
}

/**
 * @brief adds a key/value pair to a HashTable
 * @param hashTable the HashTable to add to
 * @param key the key to add or whose value to replace
 * @param value the value associated with the key
 * @return YES if successful, NO if an error was encountered
 */
int
ht_put (struct HashTable *hashTable,
        const void *key,
        const unsigned int keylen, void *value, const unsigned int valuelen)
{
  long hashValue;
  KeyValuePair *pair;

  if (key == NULL || value == NULL)
    return NO;

  hashValue = weakHash (key, keylen) % hashTable->numOfBuckets;
  pair = hashTable->bucketArray[hashValue];

  while (pair)
    {
      if (pair->keylen == keylen)
        if (memcmp (key, pair->key, keylen) == 0)
          break;
      pair = pair->next;
    }

  if (pair)
    {
      pair->key = REALLOC (pair->key, keylen);
      memcpy (pair->key, key, keylen);
      pair->keylen = keylen;

      pair->key = REALLOC (value, valuelen);
      memcpy (pair->value, value, valuelen);
      pair->valuelen = valuelen;
    }
  else
    {
      KeyValuePair *newPair = MALLOC (sizeof (KeyValuePair));
      if (newPair == NULL)
        return NO;
      else
        {
          newPair->key = MALLOC (keylen);
          memcpy (newPair->key, key, keylen);
          newPair->keylen = keylen;
          newPair->value = MALLOC (valuelen);
          memcpy (newPair->value, value, valuelen);
          newPair->valuelen = valuelen;
          newPair->next = hashTable->bucketArray[hashValue];
          hashTable->bucketArray[hashValue] = newPair;
          hashTable->numOfElements++;

          if (hashTable->upperRehashThreshold > hashTable->idealRatio)
            {
              float elementToBucketRatio = (float) hashTable->numOfElements /
                (float) hashTable->numOfBuckets;
              if (elementToBucketRatio > hashTable->upperRehashThreshold)
                ht_rehash (hashTable, 0);
            }
        }
    }

  return YES;
}

/**
 * @brief retrieves the value of a key in a HashTable
 * @param hashTable the HashTable to search
 * @param key the key whose value is desired
 * @param value the corresponding value
 * @param valuelen the length of the value
 * @return YES if found, NO otherwise
 */
int
ht_get (const struct HashTable *hashTable,
        const void *key,
        const unsigned int keylen, void **value, unsigned int *valuelen)
{
  long hashValue = weakHash (key, keylen) % hashTable->numOfBuckets;
  KeyValuePair *pair = hashTable->bucketArray[hashValue];

  while (pair != NULL && keylen != pair->keylen
         && memcmp (key, pair->key, keylen) != 0)
    pair = pair->next;

  if (pair != NULL)
    {
      *value = pair->value;
      *valuelen = pair->valuelen;
    }

  return pair != NULL;
}

/**
 * @brief removes a key/value pair from a HashTable
 * @param hashTable the HashTable to remove the key/value pair from
 * @param key the key specifying the key/value pair to be removed
 */
void
ht_remove (struct HashTable *hashTable,
           const void *key, const unsigned int keylen)
{
  long hashValue = weakHash (key, keylen) % hashTable->numOfBuckets;
  KeyValuePair *pair = hashTable->bucketArray[hashValue];
  KeyValuePair *previousPair = NULL;

  while (pair != NULL && pair->keylen != keylen &&
         memcmp (pair->key, key, keylen) != 0)
    {
      previousPair = pair;
      pair = pair->next;
    }

  if (pair != NULL)
    {
      FREE (pair->key);
      FREE (pair->value);
      if (previousPair != NULL)
        previousPair->next = pair->next;
      else
        hashTable->bucketArray[hashValue] = pair->next;
      FREE (pair);
      hashTable->numOfElements--;

      if (hashTable->lowerRehashThreshold > 0.0)
        {
          float elementToBucketRatio = (float) hashTable->numOfElements /
            (float) hashTable->numOfBuckets;
          if (elementToBucketRatio < hashTable->lowerRehashThreshold)
            ht_rehash (hashTable, 0);
        }
    }
}

/**
 * @brief removes all key/value pairs from a HashTable
 * @param hashTable the HashTable to remove all key/value pairs from
 */
void
ht_removeAll (struct HashTable *hashTable)
{
  int i;

  for (i = 0; i < hashTable->numOfBuckets; i++)
    {
      KeyValuePair *pair = hashTable->bucketArray[i];
      while (pair != NULL)
        {
          KeyValuePair *nextPair = pair->next;
          FREE (pair->key);
          FREE (pair->value);
          FREE (pair);
          pair = nextPair;
        }
      hashTable->bucketArray[i] = NULL;
    }

  hashTable->numOfElements = 0;
  ht_rehash (hashTable, 5);
}

/**
 * @brief returns the number of elements in a HashTable
 * @param hashTable the HashTable whose size is requested
 * @return the number of key/value pairs that are present in
 *         the specified HashTable
 */
long
ht_size (const struct HashTable *hashTable)
{
  return hashTable->numOfElements;
}

/**
 * @brief returns the number of buckets in a HashTable
 * @param hashTable the HashTable whose number of buckets is requested
 * @return the number of buckets that are in the specified
 *         HashTable
 */
long
ht_buckets (const struct HashTable *hashTable)
{
  return hashTable->numOfBuckets;
}

/**
 * @brief reorganizes a HashTable to be more efficient
 * @param hashTable the HashTable to be reorganized
 * @param numOfBuckets the number of buckets to rehash the HashTable to.
 *                     Should be prime.  Ideally, the number of buckets
 *                     should be between 1/5 and 1 times the expected
 *                     number of elements in the HashTable.  Values much
 *                     more or less than this will result in wasted memory
 *                     or decreased performance respectively.  If 0 is
 *                     specified, an appropriate number of buckets is
 *                     automatically calculated.
 */
void
ht_rehash (struct HashTable *hashTable, long numOfBuckets)
{
  KeyValuePair **newBucketArray;
  int i;

  if (numOfBuckets == 0)
    numOfBuckets = calculateIdealNumOfBuckets (hashTable);

  if (numOfBuckets == hashTable->numOfBuckets)
    return;                     /* already the right size! */

  newBucketArray = (KeyValuePair **)
    MALLOC (numOfBuckets * sizeof (KeyValuePair *));
  if (newBucketArray == NULL)
    {
      /* Couldn't allocate memory for the new array.  This isn't a fatal
       * error; we just can't perform the rehash. */
      return;
    }

  for (i = 0; i < numOfBuckets; i++)
    newBucketArray[i] = NULL;

  for (i = 0; i < hashTable->numOfBuckets; i++)
    {
      KeyValuePair *pair = hashTable->bucketArray[i];
      while (pair != NULL)
        {
          KeyValuePair *nextPair = pair->next;
          long hashValue = weakHash (pair->key, pair->keylen) % numOfBuckets;
          pair->next = newBucketArray[hashValue];
          newBucketArray[hashValue] = pair;
          pair = nextPair;
        }
    }

  FREE (hashTable->bucketArray);
  hashTable->bucketArray = newBucketArray;
  hashTable->numOfBuckets = numOfBuckets;
}

/**
 * @brief sets the ideal element-to-bucket ratio of a HashTable
 * @param hashTable a HashTable
 * @param idealRatio the ideal element-to-bucket ratio.  When a rehash
 *                   occurs (either manually via a call to the
 *                   HashTableRehash() function or automatically due the
 *                   the triggering of one of the thresholds below), the
 *                   number of buckets in the HashTable will be
 *                   recalculated to be a prime number that achieves (as
 *                   closely as possible) this ideal ratio.  Must be a
 *                   positive number.
 * @param lowerRehashThreshold the element-to-bucket ratio that is considered
 *                     unacceptably low (i.e., too few elements per bucket).
 *                     If the actual ratio falls below this number, a
 *                     rehash will automatically be performed.  Must be
 *                     lower than the value of idealRatio.  If no ratio
 *                     is considered unacceptably low, a value of 0.0 can
 *                     be specified.
 * @param upperRehashThreshold the element-to-bucket ratio that is considered
 *                     unacceptably high (i.e., too many elements per bucket).
 *                     If the actual ratio rises above this number, a
 *                     rehash will automatically be performed.  Must be
 *                     higher than idealRatio.  However, if no ratio
 *                     is considered unacceptably high, a value of 0.0 can
 *                     be specified.
 */
void
ht_setIdealRatio (struct HashTable *hashTable,
                  float idealRatio,
                  float lowerRehashThreshold, float upperRehashThreshold)
{

  if (idealRatio <= 0.0 || lowerRehashThreshold >= idealRatio ||
      (upperRehashThreshold != 0.0 || upperRehashThreshold <= idealRatio))
    return;

  hashTable->idealRatio = idealRatio;
  hashTable->lowerRehashThreshold = lowerRehashThreshold;
  hashTable->upperRehashThreshold = upperRehashThreshold;
}


/* end of hashtable.c */

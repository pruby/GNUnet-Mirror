/*
 * @file applications/sqstore_sqlite/sqlitetest.c
 * @brief Test for the sqstore implementations.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_sqstore_service.h"
#include "core.h"

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE; } } while (0)

static cron_t now;

static Datastore_Value * initValue(int i) {
  Datastore_Value * value;

  value = MALLOC(sizeof(Datastore_Value) + 8 * i);
  value->size = htonl(sizeof(Datastore_Value) + 8 * i);
  value->type = htonl(i);
  value->prio = htonl(i);
  value->anonymityLevel = htonl(i);
  value->expirationTime = htonll(now - i * cronSECONDS);
  memset(&value[1], i, 8*i);
  return value;
}

static int checkValue(const HashCode512 * key,
		      const Datastore_Value * val,
		      void * closure) {
  int i;
  int ret;
  Datastore_Value * value;

  i = *(int*) closure;
  value = initValue(i+1);
  if ( ( value->size == val->size) &&
       (0 == memcmp(val,
		    value,
		    ntohl(val->size)) ) ) {
    ret = OK;
  } else {
    fprintf(stderr, "Invalid value!\n");
    ret = SYSERR;		
  }
  FREE(value);
  return ret;
}

static int iterateUp(const HashCode512 * key,
		     const Datastore_Value * val,
		     int * closure) {
  int ret;

  ret = checkValue(key, val, closure);
  (*closure) += 2;
  return ret;
}

static int iterateUp1(const HashCode512 * key,
		      const Datastore_Value * val,
		      int * closure) {
  int ret;

  ret = checkValue(key, val, closure);
  (*closure) += 1;
  return ret;
}

static int iterateDown(const HashCode512 * key,
		       const Datastore_Value * val,
		       int * closure) {
  int ret;

  (*closure) -= 2;
  ret = checkValue(key, val, closure);
  return ret;
}


static int iterateDelete(const HashCode512 * key,
		       const Datastore_Value * val,
			   SQstore_ServiceAPI * api) {
  if (1 == api->del(key, val))
	return OK;
  else
	return SYSERR;
}

static int priorityCheck(const HashCode512 * key,
			 const Datastore_Value * val,
			 int * closure) {
  int id;

  id = (*closure);
  if (id == ntohl(val->prio))
    return OK;
  else
    return SYSERR;
}

static int multipleCheck(const HashCode512 * key,
			 const Datastore_Value * val,
			 Datastore_Value ** last) {
  if (*last != NULL) {
    if ( ((*last)->size == val->size) &&
	 (0 == memcmp(*last,
		      val,
		      ntohl(val->size)) ) )
      return SYSERR; /* duplicate! */
    FREE(*last);
  }
  *last = MALLOC(ntohl(val->size));
  memcpy(*last,
	 val,
	 ntohl(val->size));
  return OK;
}


/**
 * Add testcode here!
 */
static int test(SQstore_ServiceAPI * api) {
  Datastore_Value * value;
  HashCode512 key;
  unsigned long long oldSize;
  int i;

  cronTime(&now);
  oldSize = api->getSize();
  for (i=0;i<256;i++) {
    value = initValue(i+1);
    memset(&key, 256-i, sizeof(HashCode512));
    api->put(&key, value);
    FREE(value);
  }
  ASSERT(oldSize < api->getSize());
  ASSERT(256 == api->iterateLowPriority(ANY_BLOCK,
					NULL,
					NULL));
  i = 0;
  ASSERT(256 == api->iterateLowPriority(ANY_BLOCK,
					(Datum_Iterator) &iterateUp1,
					&i));
  for (i=255;i>=0;i--) {
    memset(&key, 256-i, sizeof(HashCode512));
    ASSERT(1 == api->get(&key, i+1, &checkValue, &i));
  }

  oldSize = api->getSize();
  for (i=255;i>=0;i-=2) {
    memset(&key, 256-i, sizeof(HashCode512));
    value = initValue(i+1);
    ASSERT(1 == api->del(&key, value));
    FREE(value);
  }
  ASSERT(oldSize > api->getSize());
  i = 0;
  ASSERT(128 == api->iterateLowPriority(ANY_BLOCK,
					(Datum_Iterator) &iterateUp,
					&i));
  ASSERT(256 == i);
  ASSERT(128 == api->iterateExpirationTime(ANY_BLOCK,
					   (Datum_Iterator) &iterateDown,
					   &i));
  ASSERT(0 == i);
  ASSERT(128 == api->iterateExpirationTime(ANY_BLOCK,
										   (Datum_Iterator) &iterateDelete,
										   api));
  ASSERT(0 == api->iterateExpirationTime(ANY_BLOCK,
										 (Datum_Iterator) &iterateDown,
										 &i));

  for (i=254;i>=0;i-=2) {
    memset(&key, 256-i, sizeof(HashCode512));
    value = initValue(i+1);
    ASSERT(1 == api->del(&key, value));
    FREE(value);
  }


  i = 42;
  value = initValue(i);
  memset(&key, 256-i, sizeof(HashCode512));
  api->put(&key, value);
  ASSERT(1 == api->iterateExpirationTime(ANY_BLOCK,
					 (Datum_Iterator) &priorityCheck,
					 &i));
  api->update(&key,
	      value,
	      4);
  i += 4;
  ASSERT(1 == api->iterateExpirationTime(ANY_BLOCK,
					 (Datum_Iterator) &priorityCheck,
					 &i));
  FREE(value);

  /* test multiple results */
  value = initValue(i+1);
  api->put(&key, value);
  FREE(value);

  value = NULL;
  ASSERT(2 == api->iterateExpirationTime(ANY_BLOCK,
					 (Datum_Iterator) &multipleCheck,
					 &value));
  FREE(value);
  api->del(&key,
	   NULL);
  api->del(&key,
	   NULL);
  ASSERT(0 == api->iterateExpirationTime(ANY_BLOCK,
					 NULL,
					 NULL));

  api->drop();
  return OK;
 FAILURE:
  // api->drop();
  return SYSERR;
}

/**
 * Perform option parsing from the command line.
 */
static int parser(int argc,
		  char * argv[]) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGLEVEL",
				     "WARNING"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "GNUNETD_HOME",
				     "/tmp/gnunet_test/"));
  FREENONNULL(setConfigurationString("FILES",
				     "gnunet.conf",
				     "/tmp/gnunet_test/gnunet.conf"));
  FREENONNULL(setConfigurationString("MYSQL",
				     "DATABASE",
				     "gnunetcheck"));
  return OK;
}

int main(int argc, char *argv[]) {
  SQstore_ServiceAPI * api;
  int ok;

  if (OK != initUtil(argc, argv, &parser))
    errexit(_("Could not initialize libgnunetutil!\n"));
  initCore();
  api = requestService("sqstore_mysql");
  ok = SYSERR;
  if (api != NULL) {
    api->drop();
    releaseService(api);
    api = requestService("sqstore_mysql");
    if (api != NULL) {
      ok = test(api);
      releaseService(api);
    }
  }
  doneCore();
  doneUtil();
  if (ok == SYSERR)
    return 1;
  else
    return 0;
}

/* end of mysqltest.c */

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
 * @file include/gnunet_util.h
 * @brief public interface to libgnunetutil
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_UTIL_H
#define GNUNET_UTIL_H

#ifdef MINGW
  #include <windows.h>
  #include <iphlpapi.h>
  #include <Ntsecapi.h>
  #include <lm.h>
  
  #define HAVE_STAT64 1
#endif

/* we need size_t, and since it can be both unsigned int
   or unsigned long long, this IS platform dependent;
   but "stdlib.h" should be portable 'enough' to be
   unconditionally available... */
#include <stdlib.h>


/* **************** constants ****************** */

/* do not turn this on unless you know what you
   are doing, you'll get a ton of output... */
#define DEBUG_LOCKING 0

/**
 * Just the version number of GNUnet-util implementation.
 * Encoded as
 * 0.6.1-4 => 0x00060104
 * 4.5.2   => 0x04050200
 *
 * Note that this version number is changed whenever
 * something changes GNUnet-util.  It does not have
 * to match exactly with the GNUnet version number;
 * especially the least significant bits may change
 * frequently, even between different SVN versions.
 */
#define GNUNET_UTIL_VERSION 0x00070004

/**
 * We use an unsigned short in the protocol header, thus:
 */
#define MAX_BUFFER_SIZE 65536

/**
 * Highest legal priority or trust value
 */
#define MAX_PRIO 0x7FFFFFFF

/**
 * Named constants for return values.  The following
 * invariants hold: "NO == 0" (to allow "if (NO)")
 * "OK != SYSERR", "OK != NO", "NO != SYSERR"
 * and finally "YES != NO".
 */
#define OK      1
#define SYSERR -1
#define YES     1
#define NO      0

#define STRONG YES
#define WEAK NO

/**
 * @brief constants to specify time
 */
#define cronMILLIS ((cron_t)1)
#define cronSECONDS ((cron_t)(1000 * cronMILLIS))
#define cronMINUTES ((cron_t) (60 * cronSECONDS))
#define cronHOURS ((cron_t)(60 * cronMINUTES))
#define cronDAYS ((cron_t)(24 * cronHOURS))
#define cronWEEKS ((cron_t)(7 * cronDAYS))
#define cronMONTHS ((cron_t)(30 * cronDAYS))
#define cronYEARS ((cron_t)(365 * cronDAYS))

/**
 * @brief log levels
 */
typedef enum LOG_Level {
  LOG_NOTHING = 0,
  LOG_FATAL,
  LOG_ERROR,
  LOG_FAILURE,
  LOG_WARNING,
  LOG_MESSAGE,
  LOG_INFO,
  LOG_DEBUG,
  LOG_CRON,
  LOG_EVERYTHING,
} LOG_Level;

/**
 * @brief length of the sessionkey in bytes (256 BIT sessionkey)
 */
#define SESSIONKEY_LEN (256/8)

/**
 * @brief Default names of the configuration files.
 */
#define DEFAULT_CLIENT_CONFIG_FILE "~/.gnunet/gnunet.conf"
#define DEFAULT_DAEMON_DIR "/etc"
#define DEFAULT_DAEMON_CONFIG_FILE "/etc/gnunetd.conf"
#define VAR_DIRECTORY       "/var/lib"
#define VAR_DAEMON_DIRECTORY       "/var/lib/GNUnet"
#define VAR_DAEMON_CONFIG_FILE     "/var/lib/GNUnet/gnunetd.conf"
#define HOME_DAEMON_CONFIG_FILE    "~/.gnunet/gnunetd.conf"
#define GNUNET_HOME_DIRECTORY    "~/.gnunet/"

/**
 * @brief Length of RSA encrypted data (2048 bit)
 *
 * We currently do not handle encryption of data
 * that can not be done in a single call to the
 * RSA methods (read: large chunks of data).
 * We should never need that, as we can use
 * the hash for larger pieces of data for signing,
 * and for encryption, we only need to encode sessionkeys!
 */
#define RSA_ENC_LEN 256

/**
 * Length of an RSA KEY (d,e,len), 2048 bit (=256 octests) key d, 2 byte e
 */
#define RSA_KEY_LEN 258


#define HELP_HELP \
  { 'h', "help", NULL,				\
    gettext_noop("print this help") }
#define HELP_LOGLEVEL \
  { 'L', "loglevel", "LEVEL",			\
    gettext_noop("set verbosity to LEVEL") }
#define HELP_CONFIG \
  { 'c', "config", "FILENAME",			\
    gettext_noop("use configuration file FILENAME") }
#define HELP_HOSTNAME \
  { 'H', "host", "HOSTNAME",			\
    gettext_noop("specify host on which gnunetd is running") }
#define HELP_VERSION \
  { 'v', "version", NULL,			\
    gettext_noop("print the version number") }
#define HELP_VERBOSE \
  { 'V', "verbose", NULL,			\
    gettext_noop("be verbose") }
#define HELP_END \
    { 0, NULL, NULL, NULL, }

/**
 * Default "long" version of the options, use
 * "vhdc:L:H:" in the short option argument
 * to getopt_long for now.
 */
#define LONG_DEFAULT_OPTIONS \
      { "config",        1, 0, 'c' }, \
      { "version",       0, 0, 'v' }, \
      { "help",          0, 0, 'h' }, \
      { "debug",         0, 0, 'd' }, \
      { "loglevel",      1, 0, 'L' }, \
      { "host",          1, 0, 'H' }

/* **************** structs ****************** */

/**
 * The private information of an RSA key pair.
 */
struct PrivateKey;

/**
 * Header for all Client-Server communications.
 */
typedef struct {
  /**
   * The length of the struct (in bytes, including the length field itself)
   */
  unsigned short size;

  /**
   * The type of the message (XX_CS_PROTO_XXXX)
   */
  unsigned short type;

} CS_MESSAGE_HEADER;

/**
 * CS communication: simple return value
 */
typedef struct {
  /**
   * The CS header (values: sizeof(CS_returnvalue_MESSAGE), CS_PROTO_RETURN_VALUE)
   */
  CS_MESSAGE_HEADER header;

  /**
   * The return value (network byte order)
   */
  int return_value;
} CS_returnvalue_MESSAGE;

/**
 * p2p message part header
 */
typedef struct {
  /**
   * size of this MESSAGE_PART (network byte order)
   */
  unsigned short size;

  /**
   * type of the request, XX_p2p_PROTO_XXX (network byte order)
   */
  unsigned short type;
} P2P_MESSAGE_HEADER;

typedef void (*NotifyConfigurationUpdateCallback)(void);

/**
 * Type of a cron-job method.
 */
typedef void (*CronJob)(void *);

/**
 * Time for absolute times used by cron (64 bit)
 */
typedef unsigned long long cron_t;

/**
 * 32-bit timer value.
 */
typedef unsigned int TIME_T;

/* Describe the long-named options requested by the application.
   The LONG_OPTIONS argument to getopt_long or getopt_long_only is a vector
   of `struct GNoption' terminated by an element containing a name which is
   zero.

   The field `has_arg' is:
   no_argument		(or 0) if the option does not take an argument,
   required_argument	(or 1) if the option requires an argument,
   optional_argument 	(or 2) if the option takes an optional argument.

   If the field `flag' is not NULL, it points to a variable that is set
   to the value given in the field `val' when the option is found, but
   left unchanged if the option is not found.

   To have a long-named option do something other than set an `int' to
   a compiled-in constant, such as set a value from `GNoptarg', set the
   option's `flag' field to zero and its `val' field to a nonzero
   value (the equivalent single-letter option character, if there is
   one).  For long options that have a zero `flag' field, `getopt'
   returns the contents of the `val' field.  */

struct GNoption {
  const char *name;
  /* has_arg can't be an enum because some compilers complain about
     type mismatches in all the code that assumes it is an int.  */
  int has_arg;
  int *flag;
  int val;
};

/**
 * @brief an IPv4 address
 */
typedef struct {
  unsigned int addr; /* struct in_addr */
} IPaddr;

/**
 * @brief IPV4 network in CIDR notation.
 */
struct CIDRNetwork;

/**
 * @brief an IPV6 address.
 */
typedef struct {
  unsigned int addr[4]; /* struct in6_addr addr; */
} IP6addr;

/**
 * @brief IPV6 network in CIDR notation.
 */
struct CIDR6Network;

/**
 * Callback that performs logging.
 */
typedef void (*TLogProc)(const char *txt);

/**
 * Main method of a thread.
 */
typedef void * (*PThreadMain)(void*);

/**
 * Encapsulation of a pthread handle.
 */
typedef struct PTHREAD_T {
  void * internal;
} PTHREAD_T;

/**
 * @brief 512-bit hashcode
 */
typedef struct {
  unsigned int bits[512 / 8 / sizeof(unsigned int)]; /* = 16 */
} HashCode512;

/**
 * The identity of the host (basically the RIPE160 hashcode of
 * it's public key).
 */
typedef struct {
  HashCode512 hashPubKey;
} PeerIdentity;

/**
 * @brief 0-terminated ASCII encoding of a HashCode512.
 */
typedef struct {
  unsigned char encoding[104];
} EncName;

/**
 * GNUnet mandates a certain format for the encoding
 * of private RSA key information that is provided
 * by the RSA implementations.  This format is used
 * to serialize a private RSA key (typically when
 * writing it to disk).
 */
typedef struct {
  /**
   * Total size of the structure, in bytes, in big-endian!
   */
  unsigned short len;
  unsigned short sizen;/*  in big-endian! */
  unsigned short sizee;/*  in big-endian! */
  unsigned short sized;/*  in big-endian! */
  unsigned short sizep;/*  in big-endian! */
  unsigned short sizeq;/*  in big-endian! */
  unsigned short sizedmp1;/*  in big-endian! */
  unsigned short sizedmq1;/*  in big-endian! */
  /* followed by the actual values */
} PrivateKeyEncoded;

/**
 * @brief an RSA signature
 */
typedef struct {
  unsigned char sig[RSA_ENC_LEN];
} Signature;

/**
 * @brief A public key.
 */
typedef struct {
  /**
   * In big-endian, must be RSA_KEY_LEN+2
   */
  unsigned short len;
  /**
   * Size of n in key; in big-endian!
   */
  unsigned short sizen;
  /**
   * The key itself, contains n followed by e.
   */
  unsigned char key[RSA_KEY_LEN];
  /**
   * Padding (must be 0)
   */
  unsigned short padding;
} PublicKey;

/**
 * RSA Encrypted data.
 */
typedef struct {
  unsigned char encoding[RSA_ENC_LEN];
} RSAEncryptedData;


/**
 * @brief Structure for MUTual EXclusion (Mutex).
 *
 * Essentially a wrapper around pthread_mutex_t.
 */
typedef struct Mutex {
  void * internal;
} Mutex;

/**
 * @brief Semaphore abstraction implemented with pthreads
 */
typedef struct Semaphore {
  int v;
  Mutex mutex;
  /**
   * Wrapper for pthread condition variable.
   */
  void * cond;
} Semaphore;

/**
 * @brief Inter-process semaphore.
 */
typedef struct IPC_Semaphore{
  void * platform;
} IPC_Semaphore;

/**
 * Struct to refer to a GNUnet TCP connection.
 * This is more than just a socket because if the server
 * drops the connection, the client automatically tries
 * to reconnect (and for that needs connection information).
 */
typedef struct GNUNET_TCP_SOCKET {

  /**
   * the socket handle, -1 if invalid / not life
   */
  int socket;

  /**
   * the following is the IP for the remote host for client-sockets,
   * as returned by gethostbyname("hostname"); server sockets should
   * use 0.
   */
  IPaddr ip;

  /**
   * the port number, in host byte order
   */
  unsigned short port;

  /**
   * Write buffer length for non-blocking writes.
   */
  unsigned int outBufLen;

  /**
   * Write buffer for non-blocking writes.
   */
  void * outBufPending;

  Mutex readlock;
  Mutex writelock;

} GNUNET_TCP_SOCKET;

/**
 * @brief type for session keys
 */
typedef struct {
  unsigned char key[SESSIONKEY_LEN];
  int crc32; /* checksum! */
} SESSIONKEY;

/**
 * @brief IV for sym cipher
 *
 * NOTE: must be smaller (!) in size than the
 * HashCode512.
 */
typedef struct {
  unsigned char iv[SESSIONKEY_LEN/2];
} INITVECTOR;

/**
 * Method to parse the command line. The results
 * are to be stored in the configuration module.
 * @param argc the number of arguments
 * @param argv the command line arguments
 * @return OK on success, SYSERR if we should abort the
 *   initialization sequence and exit the program
 */
typedef int (*CommandLineParser)(int argc, char * argv[]);

/**
 * Function called on each file in a directory.
 * @return OK to continue to iterate,
 *  SYSERR to abort iteration with error!
 */
typedef int (*DirectoryEntryCallback)(const char * filename,
				      const char * dirName,
				      void * data);

/**
 * @brief description of a command line option (helptext)
 */
typedef struct {
  char shortArg;
  char * longArg;
  char * mandatoryArg;
  char * description;
} Help;

/**
 * @brief bloomfilter representation (opaque)
 */
struct Bloomfilter;

/**
 * Iterator over all HashCodes stored in a Bloomfilter.
 */
typedef HashCode512 * (*ElementIterator)(void * arg);

/**
 * @brief a Vector (ordered variable size set of elements), opaque
 */
struct Vector;

/**
 * @brief a hash table, opaque
 */
struct HashTable;


/* **************** Functions and Macros ************* */

/**
 * Compute the CRC32 checksum for the first len
 * bytes of the buffer.
 *
 * @param buf the data over which we're taking the CRC
 * @param len the length of the buffer in bytes
 * @return the resulting CRC32 checksum
 */
int crc32N(const void * buf, int len);

/**
 * Produce a random value.
 *
 * @param i the upper limit (exclusive) for the random number
 * @return a random value in the interval [0,i[.
 */
unsigned int randomi(unsigned int i);

/**
 * Random on unsigned 64-bit values.  We break them down into signed
 * 32-bit values and reassemble the 64-bit random value bit-wise.
 */
unsigned long long randomi64(unsigned long long u);

unsigned long long weak_randomi64(unsigned long long u);

/**
 * Get an array with a random permutation of the
 * numbers 0...n-1.
 * @param mode STRONG if the strong (but expensive) PRNG should be used, WEAK otherwise
 * @param n the size of the array
 * @return the permutation array (allocated from heap)
 */
int * permute(int mode, int n);

/**
 * Produce a cryptographically weak random value.
 *
 * @param i the upper limit (exclusive) for the random number
 * @return a random value in the interval [0,i[.
 */
unsigned int weak_randomi(unsigned int i);

/**
 * Convert a long-long to host-byte-order.
 * @param n the value in network byte order
 * @return the same value in host byte order
 */
unsigned long long ntohll(unsigned long long n);

/**
 * Convert a long long to network-byte-order.
 * @param n the value in host byte order
 * @return the same value in network byte order
 */
unsigned long long htonll(unsigned long long n);

/**
 * Convert the len characters long character sequence
 * given in input that is in the given charset
 * to UTF-8.
 * @return the converted string (0-terminated)
 */
char * convertToUtf8(const char * input,
		     size_t len,
		     const char * charset);

/**
 * Macro for assertions in GNUnet.  Use liberally and instead
 * of specific but cryptic error messages that merely refer
 * to the location of the problem but that would be evident
 * by looking at the code instead.  Do NOT use this macro if
 * an error message with context information (strerror,
 * filenames, etc.) would be useful.
 *
 * Note that a failed assertion always aborts, so do not use
 * this for errors that can be managed.
 */
#define GNUNET_ASSERT(cond)  do { if (! (cond)) errexit(_("Assertion failed at %s:%d.\n"), __FILE__, __LINE__); } while(0);

#define GNUNET_ASSERT_FL(cond, f, l)  do { if (! (cond)) errexit(_("Assertion failed at %s:%d.\n"), f, l); } while(0);


void registerConfigurationUpdateCallback
(NotifyConfigurationUpdateCallback cb);

void unregisterConfigurationUpdateCallback
(NotifyConfigurationUpdateCallback cb);

/**
 * Call all registered configuration update callbacks,
 * the configuration has changed.
 */
void triggerGlobalConfigurationRefresh(void);

/**
 * @brief Read a specific configuration file. The previous configuration
 *        will NOT be discarded if this method is invoked twice.
 * @param fn the file to read
 * @return YES on success, NO otherwise
 */
int readConfigFile(const char *fn);

/**
 * Read the specified configuration file. The previous
 * configuration will be discarded if this method is
 * invoked twice. The configuration file that is read
 * can be set using setConfigurationString on
 * section "FILES" and option "gnunet.conf".
 *
 * This method should be invoked after the options have
 * been parsed (and eventually the configuration filename
 * default has been overriden) and if gnunetd receives
 * a SIGHUP.
 */
void readConfiguration(void);

/**
 * Expand an expression of the form
 * "$FOO/BAR" to "DIRECTORY/BAR" where
 * either in the current section or
 * globally FOO is set to DIRECTORY.
 */
char * expandDollar(const char * section,
         char * orig);

/**
 * Obtain a filename from the given section and option.  If the
 * filename is not specified, die with the given error message (do not
 * die if errMsg == NULL).
 *
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 *
 * @param errMsg the errormessage, should contain two %s tokens for
 * the section and the option.
 *
 * @return the specified filename (caller must free), or NULL if no
 * filename was specified and errMsg == NULL
 */
char * getFileName(const char * section,
		   const char * option,
		   const char * errMsg);

/**
 * Check if a string in the configuration matches a given value.  This
 * method should be preferred over getConfigurationString since this
 * method can avoid making a copy of the configuration string that
 * then must be freed by the caller.
 *
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 * @param value the value to compare against
 * @return YES or NO
 */
int testConfigurationString(const char * section,
			    const char * option,
			    const char * value);

/**
 * Obtain a string from the configuration.
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 * @return a freshly allocated string, caller must free!
 *   Note that the result can be NULL if the option is not set.
 */
char * getConfigurationString(const char * section,
			      const char * option);

/**
 * Obtain an int from the configuration.
 * @param section from which section
 * @param option which option
 * @return 0 if no option is specified
 */
unsigned int getConfigurationInt(const char * section,
				 const char * option);

/**
 * Set an option.
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 * @param value the value to use, may be NULL
 * @return the previous value (or NULL if none),
 *     caller must free!
 */
char * setConfigurationString(const char * section,
			      const char * option,
			      const char * value);

/**
 * Set an option.
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 * @param value the value to use
 * @return the previous value (or 0 if none)
 */
unsigned int setConfigurationInt(const char * section,
				 const char * option,
				 const unsigned int value);

/**
 * Get the command line strings (the ones
 * remaining after getopt-style parsing).
 * @param value the values
 + @return the number of values
 */
int getConfigurationStringList(char *** value);

/**
 * Set the list of command line options (remainder after getopt style
 * parsing).
 *
 * @param value the values
 + @param count the number of values
 */
void setConfigurationStringList(char ** value,
				int count);

/**
 * @brief Check if a setting was specified in a .conf file
 * @return YES or NO
 */
int isConfigurationItemSet(const char *section, const char *option);

/**
 * Start the cron jobs.
 */
void startCron(void);

/**
 * Stop the cron service.
 */
void stopCron(void);

/**
 * Stop running cron-jobs for a short time.  This method may only be
 * called by a thread that is not holding any locks.  It will cause
 * a deadlock if this method is called from within a cron-job.
 * Use with caution.
 */
void suspendCron(void);

/**
 * Resume running cron-jobs.
 */
void resumeCron(void);

/**
 * Is the cron-thread currently running?
 */
int isCronRunning(void);

/**
 * Like suspendCron, but does nothing if called from
 * within a cron-job.
 */
void suspendIfNotCron(void);

/**
 * Like resumeCron, but does nothing if called from
 * within a cron-job.
 */
void resumeIfNotCron(void);

/**
 * Get the current time (works just as "time", just
 * that we use the unit of time that the cron-jobs use).
 * @param setme will set the current time if non-null
 * @return the current time
 */
cron_t cronTime(cron_t * setme);

/**
 * Add a cron-job to the delta list.
 * @param method which method should we run
 * @param delta how many milliseconds until we run the method
 * @param deltaRepeat if this is a periodic, the time between
 *        the runs, otherwise 0.
 * @param data argument to pass to the method
 */
void addCronJob(CronJob method,
		unsigned int delta,
		unsigned int deltaRepeat,
		void * data);

/**
 * If the specified cron-job exists in th delta-list, move it to the
 * head of the list.  If it is running, do nothing.  If it is does not
 * exist and is not running, add it to the list to run it next.
 *
 * @param method which method should we run
 * @param deltaRepeat if this is a periodic, the time between
 *        the runs, otherwise 0.
 * @param data extra argument to calls to method, freed if
 *        non-null and cron is shutdown before the job is
 *        run and/or delCronJob is called
 */
void advanceCronJob(CronJob method,
		   unsigned int deltaRepeat,
		   void * data);
/**
 * Remove all matching cron-jobs from the list. This method should
 * only be called while cron is suspended or stopped, or from a cron
 * job that deletes another cron job.  If cron is not suspended or
 * stopped, it may be running the method that is to be deleted, which
 * could be bad (in this case, the deletion will not affect the
 * running job and may return before the running job has terminated).
 *
 * @param method which method is listed?
 * @param repeat which repeat factor was chosen?
 * @param data what was the data given to the method
 * @return the number of jobs removed
 */
int delCronJob(CronJob method,
	       unsigned int repeat,
	       void * data);

/**
 * Sleep for the specified time interval.
 * A signal interrupts the sleep.  Caller
 * is responsible to check that the sleep was
 * long enough.
 *
 * @return 0 if there was no interrupt, 1 if there was, -1 on error.
 */
int gnunet_util_sleep(cron_t delay);

/**
 * Load dynamic library
 */
void * loadDynamicLibrary(const char * libprefix,
			  const char * dsoname);

void * bindDynamicMethod(void * libhandle,
			 const char * methodprefix,
			 const char * dsoname);

void * trybindDynamicMethod(void * libhandle,
			    const char * methodprefix,
			    const char * dsoname);

void unloadDynamicLibrary(void * libhandle);

/* For communication from `getopt' to the caller.
   When `getopt' finds an option that takes an argument,
   the argument value is returned here.
   Also, when `ordering' is RETURN_IN_ORDER,
   each non-option ARGV-element is returned here.  */

extern char *GNoptarg;

/* Index in ARGV of the next element to be scanned.
   This is used for communication to and from the caller
   and for communication between successive calls to `getopt'.

   On entry to `getopt', zero means this is the first call; initialize.

   When `getopt' returns -1, this is the index of the first of the
   non-option elements that the caller should itself scan.

   Otherwise, `GNoptind' communicates from one call to the next
   how much of ARGV has been scanned so far.  */

extern int GNoptind;

/* Callers store zero here to inhibit the error message `getopt' prints
   for unrecognized options.  */

extern int GNopterr;

/* Set to an option character which was unrecognized.  */

extern int GNoptopt;


int GNgetopt_long (int argc,
		   char *const *argv,
		   const char *shortopts,
		   const struct GNoption *longopts,
		   int *longind);


/**
 * Parse a network specification. The argument specifies
 * a list of networks. The format is
 * <tt>[network/netmask;]*</tt> (no whitespace, must be terminated
 * with a semicolon). The network must be given in dotted-decimal
 * notation. The netmask can be given in CIDR notation (/16) or
 * in dotted-decimal (/255.255.0.0).
 * <p>
 * @param routeList a string specifying the forbidden networks
 * @return the converted list, NULL if the synatx is flawed
 */
struct CIDRNetwork * parseRoutes(const char * routeList);


/**
 * Check if the given IP address is in the list of
 * IP addresses.
 * @param list a list of networks
 * @param ip the IP to check (in network byte order)
 * @return NO if the IP is not in the list, YES if it it is
 */
int checkIPListed(const struct CIDRNetwork * list,
		  IPaddr ip);

/**
 * Check if the given IP address is in the list of
 * IP addresses.
 * @param list a list of networks
 * @param ip the IP to check (in network byte order)
 * @return NO if the IP is not in the list, YES if it it is
 */
int checkIP6Listed(const struct CIDR6Network * list,
		   const IP6addr * ip);

/**
 * Parse a network specification. The argument specifies
 * a list of networks. The format is
 * <tt>[network/netmask;]*</tt> (no whitespace, must be terminated
 * with a semicolon). The network must be given in dotted-decimal
 * notation. The netmask can be given in CIDR notation (/16) or
 * in dotted-decimal (/255.255.0.0).
 * <p>
 * @param routeList a string specifying the forbidden networks
 * @return the converted list, NULL if the synatx is flawed
 */
struct CIDR6Network * parseRoutes6(const char * routeList);

/* use IFLOG(LOG_XXX, statement(s)) for statements
   that should only be executed if we are at the
   right loglevel */
#define IFLOG(a,b) {if (getLogLevel() >= a) {b;} }

void LOGHASH(size_t size,
	     const void * data);

#define PRIP(ip) (unsigned int)(((unsigned int)(ip))>>24), (unsigned int)((((unsigned)(ip)))>>16 & 255), (unsigned int)((((unsigned int)(ip)))>>8 & 255), (unsigned int)((((unsigned int)(ip))) & 255)

/**
 * Get the current loglevel.
 */
LOG_Level getLogLevel(void);

/**
 * Return the logfile
 */
void *getLogfile(void);

/**
 * errexit - log an error message and exit.
 *
 * @param format the string describing the error message
 */
void errexit(const char *format, ...);

/**
 * Register an additional logging function which gets
 * called whenever GNUnet LOG()s something
 *
 * @param proc the function to register
 */
void setCustomLogProc(TLogProc proc);

/**
 * Log a message.
 * @param minLogLevel the minimum loglevel that we must be at
 * @param format the format string describing the message
 */
void LOG(LOG_Level minLogLevel,
	 const char * format,
	 ...);

#define BREAK() do { breakpoint_(__FILE__,__LINE__); } while(0);

#define BREAK_FL(f, n) do { breakpoint_(f,n); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define LOG_STRERROR(level, cmd) do { LOG(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, STRERROR(errno)); } while(0);

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_STRERROR(cmd) do { errexit(_("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, STRERROR(errno)); } while(0);

#define DIE_STRERROR_FL(cmd, f, l) do { errexit(_("`%s' failed at %s:%d with error: %s\n"), cmd, f, l, STRERROR(errno)); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_FILE_STRERROR(level, cmd, filename) do { LOG(level, _("`%s' failed on file `%s' at %s:%d with error: %s\n"), cmd, filename, __FILE__, __LINE__, STRERROR(errno)); } while(0);

#define LOG_FILE_STRERROR_FL(level, cmd, filename, f, l) do { LOG(level, _("`%s' failed on file `%s' at %s:%d with error: %s\n"), cmd, filename, f, l, STRERROR(errno)); } while(0);

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define DIE_FILE_STRERROR(cmd, filename) do { errexit(_("`%s' failed on file `%s' at %s:%d with error: %s\n"), cmd, filename, __FILE__, __LINE__, STRERROR(errno)); } while(0);

/**
 * gdb breakpoint
 */
void breakpoint_(const char * filename,
                 const int linenumber);


/**
 * Allocate memory. Checks the return value, aborts if no more
 * memory is available.  Don't use xmalloc_ directly. Use the
 * MALLOC macro.
 */
void * xmalloc_(size_t size,
		const char * filename,
		const int linenumber);

/**
 * Allocate memory.  This function does not check if the
 * allocation request is within reasonable bounds, allowing
 * allocations larger than 40 MB.  If you don't expect the
 * possibility of very large allocations, use MALLOC instead.
 */
void * xmalloc_unchecked_(size_t size,
			  const char * filename,
			  const int linenumber);

/**
 * Wrapper around malloc. Allocates size bytes of memory.
 * @param size the number of bytes to allocate
 * @return pointer to size bytes of memory
 */
#define MALLOC(size) xmalloc_(size, __FILE__,__LINE__)

/**
 * Reallocate memory. Checks the return value, aborts if no more
 * memory is available.
 */
void * xrealloc_(void * ptr,
		 const size_t n,
		 const char * filename,
		 const int linenumber);

/**
 * Wrapper around realloc. Rellocates size bytes of memory.
 * @param ptr the pointer to reallocate
 * @param size the number of bytes to reallocate
 * @return pointer to size bytes of memory
 */
#define REALLOC(ptr, size) xrealloc_(ptr, size, __FILE__,__LINE__)

/**
 * Free memory. Merely a wrapper for the case that we
 * want to keep track of allocations.  Don't use xfree_
 * directly. Use the FREE macro.
 */
void xfree_(void * ptr,
	    const char * filename,
	    const int linenumber);

/**
 * Wrapper around free. Frees the memory referred to by ptr.
 * Note that is is generally better to free memory that was
 * allocated with GROW using GROW(mem, size, 0) instead of FREE.
 *
 * @param ptr location where to free the memory. ptr must have
 *     been returned by STRDUP, MALLOC or GROW earlier.
 */
#define FREE(ptr) xfree_(ptr, __FILE__, __LINE__)

/**
 * Free the memory pointed to by ptr if ptr is not NULL.
 * Equivalent to if (ptr!=null)FREE(ptr).
 * @param ptr the location in memory to free
 */
#define FREENONNULL(ptr) do { void * __x__ = ptr; if (__x__ != NULL) { FREE(__x__); } } while(0)

/**
 * Dup a string. Don't call xstrdup_ directly. Use the STRDUP macro.
 */
char * xstrdup_(const char * str,
		const char * filename,
		const int linenumber);

/**
 * Wrapper around STRDUP.  Makes a copy of the zero-terminated string
 * pointed to by a.
 * @param a pointer to a zero-terminated string
 * @return a copy of the string including zero-termination
 */
#define STRDUP(a) xstrdup_(a,__FILE__,__LINE__)

/**
 * Dup a string. Don't call xstrdup_ directly. Use the STRDUP macro.
 *
 * @param str the string to dup
 * @param n the maximum number of characters to copy (+1 for 0-termination)
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 * @return strdup(str)
 */
char * xstrndup_(const char * str,
		 const size_t n,
		 const char * filename,
		 const int linenumber);

/**
 * Wrapper around STRNDUP.  Makes a copy of the zero-terminated string
 * pointed to by a.
 * @param a pointer to a zero-terminated string
 * @param n the maximum number of characters to copy (+1 for 0-termination)
 * @return a copy of the string including zero-termination
 */
#define STRNDUP(a,n) xstrndup_(a,n,__FILE__,__LINE__)

/**
 * Grow an array, the new elements are zeroed out.
 * Grows old by (*oldCount-newCount)*elementSize
 * bytes and sets *oldCount to newCount.
 *
 * Don't call xgrow_ directly. Use the GROW macro.
 *
 * @param old address of the pointer to the array
 *        *old may be NULL
 * @param elementSize the size of the elements of the array
 * @param oldCount address of the number of elements in the *old array
 * @param newCount number of elements in the new array, may be 0 (then *old will be NULL afterwards)
 */
void xgrow_(void ** old,
	    size_t elementSize,
	    unsigned int * oldCount,
	    unsigned int newCount,
	    const char * filename,
	    const int linenumber);

/**
 * Grow a well-typed (!) array.  This is a convenience
 * method to grow a vector <tt>arr</tt> of size <tt>size</tt>
 * to the new (target) size <tt>tsize</tt>.
 * <p>
 *
 * Example (simple, well-typed stack):
 *
 * <pre>
 * static struct foo * myVector = NULL;
 * static int myVecLen = 0;
 *
 * static void push(struct foo * elem) {
 *   GROW(myVector, myVecLen, myVecLen+1);
 *   memcpy(&myVector[myVecLen-1], elem, sizeof(struct foo));
 * }
 *
 * static void pop(struct foo * elem) {
 *   if (myVecLen == 0) die();
 *   memcpy(elem, myVector[myVecLen-1], sizeof(struct foo));
 *   GROW(myVector, myVecLen, myVecLen-1);
 * }
 * </pre>
 *
 * @param arr base-pointer of the vector, may be NULL if size is 0;
 *        will be updated to reflect the new address. The TYPE of
 *        arr is important since size is the number of elements and
 *        not the size in bytes
 * @param size the number of elements in the existing vector (number
 *        of elements to copy over)
 * @param tsize the target size for the resulting vector, use 0 to
 *        free the vector (then, arr will be NULL afterwards).
 */
#define GROW(arr,size,tsize) xgrow_((void**)&arr, sizeof(arr[0]), &size, tsize, __FILE__, __LINE__)

/**
 * TIME prototype. "man time".
 */
TIME_T TIME(TIME_T * t);

/**
 * "man ctime_r".
 * @return character sequence describing the time,
 *  must be freed by caller
 */
char * GN_CTIME(const TIME_T * t);

/**
 * Get the IP address of the given host.
 * @return OK on success, SYSERR on error
 */
int GN_getHostByName(const char * hostname,
		     IPaddr * ip);

/**
 * Give relative time in human-readable fancy format.
 */
char * timeIntervalToFancyString(cron_t delta);

/**
 * Convert a given filesize into a fancy human-readable format.
 */
char * fileSizeToFancyString(unsigned long long size);

/**
 * Create a new Session key.
 */
void makeSessionkey(SESSIONKEY * key);

/**
 * Encrypt a block with the public key of another
 * host that uses the same cyper.
 * @param block the block to encrypt
 * @param len the size of the block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @returns the size of the encrypted block, -1 for errors
 */
int encryptBlock(const void * block,
		 unsigned short len,
		 const SESSIONKEY * sessionkey,
		 const INITVECTOR * iv,
		 void * result);

/**
 * Decrypt a given block with the sessionkey.
 * @param sessionkey the key used to decrypt
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size how big is the block?
 * @param iv the initialization vector to use
 * @param result address to store the result at
 * @return -1 on failure, size of decrypted block on success
 */
int decryptBlock(const SESSIONKEY * sessionkey,
		 const void * block,
		 unsigned short size,
		 const INITVECTOR * iv,
		 void * result);

#define SEMAPHORE_NEW(value) semaphore_new_(value, __FILE__, __LINE__)
#define SEMAPHORE_FREE(s) semaphore_free_(s, __FILE__, __LINE__)
#define SEMAPHORE_DOWN(s) semaphore_down_(s, __FILE__, __LINE__)
#define SEMAPHORE_DOWN_NONBLOCKING(s) semaphore_down_nonblocking_(s, __FILE__, __LINE__)
#define SEMAPHORE_UP(s) semaphore_up_(s, __FILE__, __LINE__)

#if DEBUG_LOCKING
#define MUTEX_CREATE(a) do { \
  fprintf(stderr, \
          "Creating mutex %x at line %d in file %s\n", \
          (int) a, __LINE__, __FILE__); \
  create_mutex_(a); \
}\
while(0)
#define MUTEX_CREATE_RECURSIVE(a) do { \
  fprintf(stderr, \
          "Creating recursive mutex %x at line %d in file %s\n", \
          (int) a, __LINE__, __FILE__); \
  create_recursive_mutex_(a); \
}\
while(0)
#define MUTEX_DESTROY(a) do { \
  fprintf(stderr, \
          "Destroying mutex %x at line %d in file %s\n", \
          (int) a, __LINE__, __FILE__); \
  destroy_mutex_(a); \
}\
while(0)
#define MUTEX_LOCK(a) do { \
  fprintf(stderr, \
          "Aquireing lock %x at %s:%d\n", \
          (int)a, __FILE__, __LINE__); \
  mutex_lock_(a, __FILE__, __LINE__); \
}\
while (0)
#define MUTEX_UNLOCK(a) do { \
  fprintf(stderr, \
         "Releasing lock %x at %s:%d\n", \
	(int)a, __FILE__, __LINE__); \
  mutex_unlock_(a, __FILE__, __LINE__); \
}\
while (0)
#else
#define MUTEX_LOCK(a) mutex_lock_(a, __FILE__, __LINE__)
#define MUTEX_UNLOCK(a) mutex_unlock_(a, __FILE__, __LINE__)
#define MUTEX_CREATE(a) create_mutex_(a)
#define MUTEX_CREATE_RECURSIVE(a) create_recursive_mutex_(a)
#define MUTEX_DESTROY(a) destroy_mutex_(a)
#endif

/**
 * Returns YES if pt is the handle for THIS thread.
 */
int PTHREAD_SELF_TEST(PTHREAD_T * pt);

/**
 * Get the handle for THIS thread.
 */
void PTHREAD_GET_SELF(PTHREAD_T * pt);

/**
 * Release handle for a thread (should have been
 * obtained using PTHREAD_GET_SELF).
 */
void PTHREAD_REL_SELF(PTHREAD_T * pt);

/**
 * Create a thread. Use this method instead of pthread_create since
 * BSD may only give a 1k stack otherwise.
 *
 * @param handle handle to the pthread (for detaching, join)
 * @param main the main method of the thread
 * @param arg the argument to main
 * @param stackSize the size of the stack of the thread in bytes.
 *        Note that if the stack overflows, some OSes (seen under BSD)
 *        will just segfault and gdb will give a messed-up stacktrace.
 * @return see pthread_create
 */
int PTHREAD_CREATE(PTHREAD_T * handle,
		   PThreadMain main,
		   void * arg,
		   size_t stackSize);

void PTHREAD_JOIN(PTHREAD_T * handle,
		  void ** ret);

void PTHREAD_KILL(PTHREAD_T * handle,
		  int signal);

void PTHREAD_DETACH(PTHREAD_T * handle);

#define IPC_SEMAPHORE_NEW(name,value) ipc_semaphore_new_(name, value, __FILE__, __LINE__)
#define IPC_SEMAPHORE_FREE(s) ipc_semaphore_free_(s, __FILE__, __LINE__)
#define IPC_SEMAPHORE_DOWN(s) ipc_semaphore_down_(s, __FILE__, __LINE__)
#define IPC_SEMAPHORE_UP(s) ipc_semaphore_up_(s, __FILE__, __LINE__)

IPC_Semaphore * ipc_semaphore_new_(const char * basename,
				   const unsigned int initialValue,
				   const char * filename,
				   const int linenumber);

void ipc_semaphore_up_(IPC_Semaphore * sem,
		       const char * filename,
		       const int linenumber);

void ipc_semaphore_down_(IPC_Semaphore * sem,
			 const char * filename,
			 const int linenumber);


void ipc_semaphore_free_(IPC_Semaphore * sem,
			 const char * filename,
			 const int linenumber);

/**
 * While we must define these globally to make the
 * compiler happy, always use the macros in the sources
 * instead!
 */
void create_mutex_(Mutex * mutex);
void create_recursive_mutex_(Mutex * mutex);
void create_fast_mutex_(Mutex * mutex);
void destroy_mutex_(Mutex * mutex);
void mutex_lock_(Mutex * mutex,
		 const char * filename,
		 const int linenumber);
void mutex_unlock_(Mutex * mutex,
		   const char * filename,
		   const int linenumber);
Semaphore * semaphore_new_(int value,
			   const char * filename,
			   const int linenumber);
void semaphore_free_(Semaphore * s,
		     const char * filename,
		     const int linenumber);
int semaphore_down_(Semaphore * s,
		    const char * filename,
		    const int linenumber);
int semaphore_down_nonblocking_(Semaphore * s,
				const char * filename,
				const int linenumber);
int semaphore_up_(Semaphore * s,
		  const char * filename,
		  const int linenumber);		

/**
 * Convert hash to ASCII encoding.
 * @param block the hash code
 * @param result where to store the encoding (EncName can be
 *  safely cast to char*, a '\0' termination is set).
 */
void hash2enc(const HashCode512 * block,
	      EncName * result);

/**
 * Convert ASCII encoding back to hash
 * @param enc the encoding
 * @param result where to store the hash code
 * @return OK on success, SYSERR if result has the wrong encoding
 */
int enc2hash(const char * enc,
	     HashCode512 * result);

/**
 * @brief Convert a weak 64 bit hash into a string
 * @param h the hashcode
 * @param e the string (zero terminated)
 */
void encWeakHash(unsigned long long h, char e[14]);

/**
 * Compute the distance between 2 hashcodes.
 * The computation must be fast, not involve
 * a.a or a.e (they're used elsewhere), and
 * be somewhat consistent. And of course, the
 * result should be a positive number.
 */
int distanceHashCode512(const HashCode512 * a,
			const HashCode512 * b);

/**
 * compare two hashcodes.
 */
int equalsHashCode512(const HashCode512 * a,
		      const HashCode512 * b);

/**
 * Hash block of given size.
 * @param block the data to hash, length is given as a second argument
 * @param ret pointer to where to write the hashcode
 */
void hash(const void * block,
	  unsigned int size,
	  HashCode512 * ret);


/**
 * Compute the hash of an entire file.
 * @return OK on success, SYSERR on error
 */
int getFileHash(const char * filename,
     	        HashCode512 * ret);

/**
 * @brief Create a cryptographically weak hashcode from a buffer
 * @param z the buffer to hash
 * @param n the size of z
 * @return the hashcode
 */
unsigned long long weakHash(const char *z, int n);

/**
 * Check if 2 hosts are the same (returns 1 if yes)
 * @param first the first host
 * @param second the second host
 * @returns 1 if the hosts are the same, 0 otherwise
 */
int hostIdentityEquals(const PeerIdentity * first,
		       const PeerIdentity * second);

void makeRandomId(HashCode512 * result);

/* compute result(delta) = b - a */
void deltaId(const HashCode512 * a,
	     const HashCode512 * b,
	     HashCode512 * result);

/* compute result(b) = a + delta */
void addHashCodes(const HashCode512 * a,
		  const HashCode512 * delta,
		  HashCode512 * result);

/* compute result = a ^ b */
void xorHashCodes(const HashCode512 * a,
		  const HashCode512 * b,
		  HashCode512 * result);

/**
 * Convert a hashcode into a key.
 */
void hashToKey(const HashCode512 * hc,
	       SESSIONKEY * skey,
	       INITVECTOR * iv);

/**
 * Obtain a bit from a hashcode.
 * @param code the hash to index bit-wise
 * @param bit index into the hashcode, [0...159]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int getHashCodeBit(const HashCode512 * code,
		   unsigned int bit);

/**
 * Compare function for HashCodes, producing a total ordering
 * of all hashcodes.
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
int hashCodeCompare(const HashCode512 * h1,
		    const HashCode512 * h2);

/**
 * Find out which of the two hash codes is closer to target
 * in the XOR metric (Kademlia).
 * @return -1 if h1 is closer, 1 if h2 is closer and 0 if h1==h2.
 */
int hashCodeCompareDistance(const HashCode512 * h1,
			    const HashCode512 * h2,
			    const HashCode512 * target);

/**
 * create a new hostkey. Callee must free return value.
 */
struct PrivateKey * makePrivateKey(void);

/**
 * Deterministically (!) create a hostkey using only the
 * given HashCode as input to the PRNG.
 */
struct PrivateKey * makeKblockKey(const HashCode512 * input);

/**
 * Free memory occupied by hostkey
 * @param hostkey pointer to the memory to free
 */
void freePrivateKey(struct PrivateKey * hostkey);

/**
 * Extract the public key of the host.
 * @param result where to write the result.
 */
void getPublicKey(const struct PrivateKey * hostkey,
		  PublicKey * result);

/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 * @param hostkey the hostkey to use
 * @returns encoding of the private key.
 */
PrivateKeyEncoded * encodePrivateKey(const struct PrivateKey * hostkey);

/**
 * Decode the private key from the file-format back
 * to the "normal", internal, RSA format.
 * @param encoded the encoded hostkey
 * @returns the decoded hostkey
 */
struct PrivateKey * decodePrivateKey(const PrivateKeyEncoded * encoding);

/**
 * Encrypt a block with the public key of another host that uses the
 * same cyper.
 *
 * @param block the block to encrypt
 * @param size the size of block
 * @param publicKey the encoded public key used to encrypt
 * @param target where to store the encrypted block
 * @returns SYSERR on error, OK if ok
 */
int encryptPrivateKey(const void * block,
		      unsigned short size,
		      const PublicKey * publicKey,
		      RSAEncryptedData * target);

/**
 * Decrypt a given block with the hostkey.
 *
 * @param key the key to use
 * @param block the data to decrypt, encoded as returned by encrypt, not consumed
 * @param result pointer to a location where the result can be stored
 * @param size how many bytes of a result are expected? Must be exact.
 * @returns the size of the decrypted block (that is, size) or -1 on error
 */
int decryptPrivateKey(const struct PrivateKey * key,
		      const RSAEncryptedData * block,
		      void * result,
		      unsigned short size);

/**
 * Sign a given block.
 *
 * @param block the data to sign, first unsigned short_SIZE bytes give length
 * @param size how many bytes to sign
 * @param result where to write the signature
 * @return SYSERR on error, OK on success
 */
int sign(const struct PrivateKey * key,
	 unsigned short size,
	 const void * block,
	 Signature * result);

/**
 * Verify signature.
 * @param block the signed data
 * @param len the length of the block
 * @param sig signature
 * @param publicKey public key of the signer
 * @returns OK if ok, SYSERR if invalid
 */
int verifySig(const void * block,
	      unsigned short len,
	      const Signature * sig,	
	      const PublicKey * publicKey);

/**
 * Initialize the util module.
 * @param argc the number of arguments
 * @param argv the command line arguments
 * @param parser parser to call at the right moment
 * @return OK on success, SYSERR if we should abort
 */
int initUtil(int argc,
	     char * argv[],
	     CommandLineParser parser);


/**
 * The configuration was re-loaded. All
 * util modules should check if it has
 * changed for them.
 */
void resetUtil(void);

/**
 * Shutdown the util services in proper order.
 */
void doneUtil(void);

/**
 * Configuration: get the GNUnet port for the client to
 * connect to (via TCP).
 */
unsigned short getGNUnetPort(void);

/**
 * Get a GNUnet TCP socket that is connected to gnunetd.
 */
GNUNET_TCP_SOCKET * getClientSocket(void);

/**
 * Free a Client socket.
 */
void releaseClientSocket(GNUNET_TCP_SOCKET * sock);

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param fn the hashcode representing the entry
 * @param result the buffer to write the result to
 *        (*result should be NULL, sufficient space is allocated)
 * @return the number of bytes read on success, -1 on failure
 */
int stateReadContent(const char * name,
		     void ** result);

/**
 * Append content to file.
 *
 * @param fn the key for the entry
 * @param len the number of bytes in block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
int stateAppendContent(const char * name,
		       int len,
		       const void * block);

/**
 * Write content to a file.
 *
 * @param fn the key for the entry
 * @param len the number of bytes in block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
int stateWriteContent(const char * name,
		      int len,
		      const void * block);

/**
 * Free space in the database by removing one file
 * @param name the hashcode representing the name of the file
 *        (without directory)
 */
int stateUnlinkFromDB(const char * name);

/**
 * Initialize a GNUnet client socket.
 *
 * @param port the portnumber in host byte order
 * @param hostname the name of the host to connect to
 * @param result the SOCKET (filled in)
 * @return OK if successful, SYSERR on failure
 */
int initGNUnetClientSocket(unsigned short port,
			   const char * hostname,
			   GNUNET_TCP_SOCKET * result);

/**
 * Initialize a GNUnet client socket.
 *
 * @param port the portnumber in host byte order
 * @param ip IP of the host to connect to
 * @param result the SOCKET (filled in)
 * @return OK if successful, SYSERR on failure
 */
int initGNUnetClientSocketIP(unsigned short port,
			     IPaddr ip,
			     GNUNET_TCP_SOCKET * result);

/**
 * Initialize a GNUnet server socket.
 * @param sock the open socket
 * @param result the SOCKET (filled in)
 * @return OK (always successful)
 */
int initGNUnetServerSocket(int socket,
			   GNUNET_TCP_SOCKET * result);

/**
 * Check if a socket is open. Will ALWAYS return 'true'
 * for a valid client socket (even if the connection is
 * closed), but will return false for a closed server socket.
 * @return 1 if open, 0 if closed
 */
int isOpenConnection(GNUNET_TCP_SOCKET * sock);

/**
 * Check a socket, open and connect if it is closed and it is a
 * client-socket.
 */
int checkSocket(GNUNET_TCP_SOCKET * sock);

/**
 * Read from a GNUnet TCP socket.
 * @param sock the socket
 * @param buffer the buffer to write data to;
 *        if NULL == *buffer, *buffer is allocated (caller frees)
 * @return OK if the read was successful, SYSERR if the socket
 *         was closed by the other side (if the socket is a
 *         client socket and is used again, tcpio will attempt
 *         to re-establish the connection [temporary error]).
 */
int readFromSocket(GNUNET_TCP_SOCKET * sock,
		   CS_MESSAGE_HEADER ** buffer);

/**
 * Write to a GNUnet TCP socket.
 * @param sock the socket to write to
 * @param buffer the buffer to write
 * @return OK if the write was sucessful, otherwise SYSERR.
 */
int writeToSocket(GNUNET_TCP_SOCKET * sock,
		  const CS_MESSAGE_HEADER * buffer);

/**
 * Write to a GNUnet TCP socket non-blocking.
 * @param sock the socket to write to
 * @param buffer the buffer to write
 * @return OK if the write was sucessful, NO if it would have blocked and was not performed,
 *         otherwise SYSERR.
 */
int writeToSocketNonBlocking(GNUNET_TCP_SOCKET * sock,
			     const CS_MESSAGE_HEADER * buffer);

/**
 * Close a GNUnet TCP socket for now (use to temporarily close
 * a TCP connection that will probably not be used for a long
 * time; the socket will still be auto-reopened by the
 * readFromSocket/writeToSocket methods if it is a client-socket).
 */
void closeSocketTemporarily(GNUNET_TCP_SOCKET * sock);

/**
 * Destroy a socket for good. If you use this socket afterwards,
 * you must first invoke initializeSocket, otherwise the operation
 * will fail.
 */
void destroySocket(GNUNET_TCP_SOCKET * sock);


/**
 * Obtain a return value from a remote call from
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value from TCP
 * @return SYSERR on error, OK if the return value was
 *         read successfully
 */
int readTCPResult(GNUNET_TCP_SOCKET * sock,
		  int * ret);

/**
 * Send a return value to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return SYSERR on error, OK if the return value was
 *         send successfully
 */
int sendTCPResult(GNUNET_TCP_SOCKET * sock,
		  int ret);

/**
 * Get the load of the CPU relative to what is allowed.
 *
 * @return the CPU load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getCPULoad(void);

/**
 * Get the load of the network relative to what is allowed.
 * The only difference to networkUsageUp is that
 * this function averages the values over time.
 *
 * @return the network load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getNetworkLoadUp(void);

/**
 * Get the load of the network relative to what is allowed.
 * The only difference to networkUsageDown is that
 * this function averages the values over time.
 *
 * @return the network load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getNetworkLoadDown(void);

/**
 * Tell statuscalls to increment the number of bytes sent
 */
void incrementBytesSent(unsigned long long delta);

/**
 * Tell statuscalls to increment the number of bytes received
 */
void incrementBytesReceived(unsigned long long delta);

/**
 * Get the size of the file (or directory)
 * of the given file (in bytes).
 *
 * @return OK on success, SYSERR on error
 */
int getFileSize(const char * filename,
		unsigned long long * size);

/**
 * Get the size of the file (or directory) without
 * counting symlinks.
 *
 * @return OK on success, SYSERR on error
 */
int getFileSizeWithoutSymlinks(const char * filename,
			       unsigned long long * size);

/**
 * Get the number of blocks that are left on the partition that
 * contains the given file (for normal users).
 *
 * @param part a file on the partition to check
 * @return -1 on errors, otherwise the number of free blocks
 */
long getBlocksLeftOnDrive(const char * part);

/**
 * Assert that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 * @returns 1 if yes, 0 if not (will print an error
 * message in that case, too).
 */
int assertIsFile(const char * fil);

/**
 * Complete filename (a la shell) from abbrevition.
 * @param fil the name of the file, may contain ~/ or
 *        be relative to the current directory
 * @returns the full file name,
 *          NULL is returned on error
 */
char * expandFileName(const char * fil);

/**
 * Implementation of "mkdir -p"
 * @param dir the directory to create
 * @returns SYSERR on failure, OK otherwise
 */
int mkdirp(const char * dir);

/**
 * Read the contents of a binary file into a buffer.
 * @param fileName the name of the file, not freed,
 *        must already be expanded!
 * @param len the maximum number of bytes to read
 * @param result the buffer to write the result to
 * @return the number of bytes read on success, -1 on failure
 */
int readFile(const char * fileName,
	     int len,
	     void * result);

/**
 * Write a buffer to a file.
 * @param fileName the name of the file, NOT freed!
 * @param buffer the data to write
 * @param n number of bytes to write
 * @param mode the mode for file permissions
 * @return OK on success, SYSERR on error
 */
int writeFile(const char * fileName,
	      const void * buffer,
	      unsigned int n,
	      const char * mode);

/**
 * Copy a file.
 * @return OK on success, SYSERR on error
 */
int copyFile(const char * src,
	     const char * dst);

/**
 * Scan a directory for files. The name of the directory
 * must be expanded first (!).
 * @param dirName the name of the directory
 * @param callback the method to call for each file
 * @param data argument to pass to callback
 * @return the number of files found, -1 on error
 */
int scanDirectory(const char * dirName,
		  DirectoryEntryCallback callback,
		  void * data);

/**
 * Test if fil is a directory.
 * @returns YES if yes, NO if not
 */
int isDirectory(const char * fil);

/**
 * Remove all files in a directory (rm -rf). Call with
 * caution.
 *
 *
 * @param fileName the file to remove
 * @return OK on success, SYSERR on error
 */
int rm_minus_rf(const char * fileName);

/* use the CLOSE macro... */
void close_(int fd, const char * filename, int linenumber);

#define closefile(fd) close_(fd, __FILE__, __LINE__)

/**
 * Stop the application.
 * @param signum is ignored
 */
void run_shutdown(int signum);

/**
 * Test if the shutdown has been initiated.
 * @return YES if we are shutting down, NO otherwise
 */
int testShutdown(void);

/**
 * Initialize the signal handlers, etc.
 */
void initializeShutdownHandlers(void);

/**
 * Wait until the shutdown has been initiated.
 */
void wait_for_shutdown(void);

void doneShutdownHandlers(void);

/**
 * Print output of --help in GNU format.
 */
void formatHelp(const char * general,
		const char * description,
		const Help * opt);

/**
 * Parse the default set of options and set
 * options in the configuration accordingly.
 * This does not include --help or --version.
 * @return YES if the option was a default option
 *  that was successfully processed
 */
int parseDefaultOptions(char c,
			char * optarg);

/**
 * Load a bloom-filter from a file.
 * @param filename the name of the file (or the prefix)
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use)
 * @param k the number of hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
struct Bloomfilter * loadBloomfilter(const char * filename,
				     unsigned int size,
				     unsigned int k);

/**
 * Test if an element is in the filter.
 * @param e the element
 * @param bf the filter
 * @return YES if the element is in the filter, NO if not
 */
int testBloomfilter(struct Bloomfilter * bf,
		    const HashCode512 * e);

/**
 * Add an element to the filter
 * @param bf the filter
 * @param e the element
 */
void addToBloomfilter(struct Bloomfilter * bf,
		      const HashCode512 * e);

/**
 * Remove an element from the filter.
 * @param bf the filter
 * @param e the element to remove
 */
void delFromBloomfilter(struct Bloomfilter * bf,
			const HashCode512 * e);

/**
 * Free the space associcated with a filter
 * in memory, flush to drive if needed (do not
 * free the space on the drive)
 * @param bf the filter
 */
void freeBloomfilter(struct Bloomfilter * bf);

/**
 * Reset a bloom filter to empty.
 * @param bf the filter
 */
void resetBloomfilter(struct Bloomfilter * bf);

/**
 * Resize a bloom filter.  Note that this operation
 * is pretty costly.  Essentially, the bloom filter
 * needs to be completely re-build.
 *
 * @param bf the filter
 * @param iterator an iterator over all elements stored in the BF
 * @param iterator_arg argument to the iterator function
 * @param size the new size for the filter
 * @param k the new number of hash-function to apply per element
 */
void resizeBloomfilter(struct Bloomfilter * bf,
		       ElementIterator iterator,
		       void * iterator_arg,
		       unsigned int size,
		       unsigned int k);

/**
 * Depending on doBlock, enable or disable the nonblocking mode
 * of socket s.
 *
 * @return Upon successful completion, it returns zero.
 * @return Otherwise -1 is returned.
 */
int setBlocking(int s, int doBlock);

/**
 * Check whether the socket is blocking
 * @param s the socket
 * @return YES if blocking, NO non-blocking
 */
int isSocketBlocking(int s);

/**
 * Do a NONBLOCKING read on the given socket.  Note that in order to
 * avoid blocking, the caller MUST have done a select call before
 * calling this function. Though the caller must be prepared to the
 * fact that this function may fail with EWOULDBLOCK in any case (Win32).
 *
 * @brief Reads at most max bytes to buf. Interrupts are IGNORED.
 * @param s socket
 * @param buf buffer
 * @param max maximum number of bytes to read
 * @param read number of bytes actually read.
 *             0 is returned if no more bytes can be read
 * @return SYSERR on error, YES on success or NO if the operation
 *         would have blocked
 */
int RECV_NONBLOCKING(int s,
		     void * buf,
		     size_t max,
		     size_t *read);


/**
 * Do a BLOCKING read on the given socket.  Read len bytes (if needed
 * try multiple reads).  Interrupts are ignored.
 *
 * @return SYSERR if len bytes could not be read,
 *   otherwise the number of bytes read (must be len)
 */
int RECV_BLOCKING_ALL(int s,
		      void * buf,
		      size_t len);


/**
 * Do a NONBLOCKING write on the given socket.
 * Write at most max bytes from buf.
 * Interrupts are ignored (cause a re-try).
 *
 * The caller must be prepared to the fact that this function
 * may fail with EWOULDBLOCK in any case (Win32).
 *
 * @param s socket
 * @param buf buffer to send
 * @param max maximum number of bytes to send
 * @param sent number of bytes actually sent
 * @return SYSERR on error, YES on success or
 *         NO if the operation would have blocked.
 */
int SEND_NONBLOCKING(int s,
		     const void * buf,
		     size_t max,
		     size_t *sent);


/**
 * Do a BLOCKING write on the given socket.  Write len bytes (if
 * needed do multiple write).  Interrupts are ignored (cause a
 * re-try).
 *
 * @return SYSERR if len bytes could not be send,
 *   otherwise the number of bytes transmitted (must be len)
 */
int SEND_BLOCKING_ALL(int s,
		      const void * buf,
		      size_t len);

/**
 * Check if socket is valid
 * @return 1 if valid, 0 otherwise
 */
int isSocketValid(int s);

/**
 * Like snprintf, just aborts if the buffer is of insufficient size.
 */
int SNPRINTF(char * buf,
	     size_t size,
	     const char * format,
	     ...);

/**
 * A debug function that dumps the vector to stderr.
 */
void vectorDump(struct Vector *v);

/**
 * @param vss Size of the VectorSegment data area. The "correct" value for this
 * is a bit of a gamble, as it depends on both the operations you
 * perform on the vectors and how much data is stored in them. In
 * general, the more data you store the bigger the segments should be,
 * or otherwise the increased length of the linked list will become a
 * bottleneck for operations that are performed on arbitrary indexes.
 */
struct Vector * vectorNew(unsigned int vss);

/**
 * Free vector structure including its data segments, but _not_ including the
 * stored void pointers. It is the user's responsibility to empty the vector
 * when necessary to avoid memory leakage.
 */
void vectorFree(struct Vector * v);

size_t vectorSize(struct Vector * v);

/**
 * Insert a new element in the vector at given index.
 * @return OK on success, SYSERR if the index is out of bounds.
 */
int vectorInsertAt(struct Vector * v,
		   void * object,
		   unsigned int index);

/**
 * Insert a new element at the end of the vector.
 */
void vectorInsertLast(struct Vector * v, void * object);

/**
 * Return the element at given index in the vector or NULL if the index is out
 * of bounds. The iterator is set to point to the returned element.
 */
void * vectorGetAt(struct Vector * v,
		   unsigned int index);

/**
 * Return the first element in the vector, whose index is 0, or NULL if the
 * vector is empty. The iterator of the vector is set to point to the first
 * element.
 */
void * vectorGetFirst(struct Vector * v);

/**
 * Return the last element in the vector or NULL if the vector is empty. The
 * iterator of the vector is set to point to the last element.
 */
void * vectorGetLast(struct Vector * v);

/**
 * Return the next element in the vector, as called after vector_get_at() or
 * vector_get_first(). The return value is NULL if there are no more elements
 * in the vector or if the iterator has not been set.
 */
void * vectorGetNext(struct Vector * v);

/**
 * Return the previous element in the vector, as called after vector_get_at()
 * or vector_get_last(). The return value is NULL if there are no more
 * elements in the vector or if the iterator has not been set.
 */
void * vectorGetPrevious(struct Vector * v);

/**
 * Delete and return the element at given index. NULL is returned if index is
 * out of bounds.
 */
void * vectorRemoveAt(struct Vector * v,
		      unsigned int index);

/**
 * Delete and return the last element in the vector, or NULL if the vector
 * is empty.
 */
void * vectorRemoveLast(struct Vector * v);

/**
 * Delete and return given object from the vector, or return NULL if the object
 * is not found.
 */
void * vectorRemoveObject(struct Vector * v, void * object);

/**
 * Set the given index in the vector. The old value of the index is
 * returned, or NULL if the index is out of bounds.
 */
void * vectorSetAt(struct Vector * v,
		   void * object,
		   unsigned int index);

/**
 * Set the index occupied by the given object to point to the new object.
 * The old object is returned, or NULL if it's not found.
 */
void * vectorSetObject(struct Vector * v,
		       void * object,
		       void * old_object);

/**
 * Swaps the contents of index1 and index2. Return value is OK
 * on success, SYSERR if either index is out of bounds.
 */
int vectorSwap(struct Vector * v,
	       unsigned int index1,
	       unsigned int index2);

/**
 * Return the index of given element or -1 if the element is not found.
 */
unsigned int vectorIndexOf(struct Vector * v,
			   void * object);

/**
 * Return the data stored in the vector as a single dynamically
 * allocated array of (void *), which must be FREEed by the caller.
 * Use the functions get_{at,first,last,next,previous} instead, unless
 * you really need to access everything in the vector as fast as
 * possible.
 */
void ** vectorElements(struct Vector * v);

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
struct HashTable *ht_create(long numOfBuckets);

/**
 * @brief destroys an existing HashTable
 * @param hashTable the HashTable to destroy
 */
void ht_destroy(struct HashTable *hashTable);

/**
 * @brief checks the existence of a key in a HashTable
 * @param hashTable the HashTable to search
 * @param key the key to search for
 * @return whether or not the specified HashTable contains the
 *         specified key
 */
int ht_containsKey(const struct HashTable *hashTable, const void *key, const unsigned int keylen);

/**
 * @brief checks the existence of a value in a HashTable
 * @param hashTable the HashTable to search
 * @param value the value to search for
 * @return whether or not the specified HashTable contains the
 *         specified value
 */
int ht_containsValue(const struct HashTable *hashTable, const void *value, const unsigned int valuelen);

/**
 * @brief adds a key/value pair to a HashTable
 * @param hashTable the HashTable to add to
 * @param key the key to add or whose value to replace
 * @param value the value associated with the key
 * @return 0 if successful, -1 if an error was encountered
 */
int ht_put(struct HashTable *hashTable, const void *key, const unsigned int keylen,
  void *value, const unsigned int valuelen);
  
/**
 * @brief retrieves the value of a key in a HashTable
 * @param hashTable the HashTable to search
 * @param key the key whose value is desired
 * @param value the corresponding value
 * @param valuelen the length of the value
 * @return YES if found, NO otherwise
 */
int ht_get(const struct HashTable *hashTable, const void *key, const unsigned int
  keylen, void **value, unsigned int *valuelen);

/**
 * @brief removes a key/value pair from a HashTable
 * @param hashTable the HashTable to remove the key/value pair from
 * @param key the key specifying the key/value pair to be removed
 */
void ht_remove(struct HashTable *hashTable, const void *key, const unsigned int keylen);

/**
 * @brief removes all key/value pairs from a HashTable
 * @param hashTable the HashTable to remove all key/value pairs from
 */
void ht_removeAll(struct HashTable *hashTable);

/**
 * @brief returns the number of elements in a HashTable
 * @param hashTable the HashTable whose size is requested
 * @return the number of key/value pairs that are present in
 *         the specified HashTable
 */
long ht_size(const struct HashTable *hashTable);

/**
 * @brief returns the number of buckets in a HashTable
 * @param hashTable the HashTable whose number of buckets is requested
 * @return the number of buckets that are in the specified
 *         HashTable
 */
long ht_buckets(const struct HashTable *hashTable);

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
void ht_rehash(struct HashTable *hashTable, long numOfBuckets);

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
void ht_setIdealRatio(struct HashTable *hashTable, float idealRatio,
        float lowerRehashThreshold, float upperRehashThreshold);

#define HT_PUT(ht, key, val) ht_put(ht, key, sizeof(key), val, sizeof(val))
#define HT_GET(ht, key, val, vallen) ht_get(ht, key, sizeof(key), val, vallen)
#define HT_CONTAINS_KEY(ht, key) ht_containsKey(ht, key, sizeof(key))
#define HT_CONTAINS_VALUE(ht, value) ht_containsValue(ht, value, sizeof(value))
#define HT_REMOVE(ht, key) ht_remove(ht, key, sizeof(key))

/**
 * open() a file
 */
int fileopen(const char *filename, int oflag, ...);

/**
 * String functions
 */
#if !HAVE_STRLCPY
size_t strlcpy(char *dest, const char *src, size_t size);
#endif
#if !HAVE_STRLCAT
size_t strlcat(char *dest, const char *src, size_t count);
#endif

/**
 * @brief Get human-readable filesizes from byte numbers
 * @param size_n the size in bytes
 */
char * getHumanSize (unsigned long long int size_n);

/**
 * @brief Enumerate all network interfaces
 * @param callback the callback function
 */
void enumNetworkIfs(void (*callback) (const char *, int, void *), void * cls);

/**
 * @brief Checks if we can start GNUnet automatically
 * @return 1 if yes, 0 otherwise
 */
int isOSAutostartCapable(void);

/**
 * @brief Make GNUnet start automatically
 * @param doAutoStart true to enable autostart, false to disable it
 * @param username name of the user account to use
 * @param groupname name of the group to use
 * @return 0 on success
 */
int autostartService(int doAutoStart, char *username, char *groupname);

/**
 * @brief Checks if we can add an user for the GNUnet service
 * @return 1 if yes, 0 otherwise
 * @todo support for useradd(8)
 */
int isOSUserAddCapable(void);

/**
 * @brief Checks if we can add a group for the GNUnet service
 * @return 1 if yes, 0 otherwise
 * @todo support for groupadd(8)
 */
int isOSGroupAddCapable(void);

/**
 * @brief Add a service account for GNUnet
 * @param group the group of the new user
 * @param name the name of the new user
 * @return 0 on success
 */
int createGroupUser(char *group_name, char *user_name);

/**
 * @brief Format a Windows specific error code
 */
char *winErrorStr(char *prefix, int dwErr);

/**
 * Checks if gnunetd is running
 *
 * Uses CS_PROTO_traffic_COUNT query to determine if gnunetd is
 * running.
 *
 * @return OK if gnunetd is running, SYSERR if not
 */
int checkGNUnetDaemonRunning(void);

/**
 * Start gnunetd process
 *
 * @param daemonize YES if gnunetd should be daemonized
 * @return pid_t of gnunetd if NOT daemonized, 0 if
 *  daemonized sucessfully, -1 on error
 */
int startGNUnetDaemon(int daemonize);


/**
 * Stop gnunetd
 *
 * Note that returning an error does NOT mean that
 * gnunetd will continue to run (it may have been
 * shutdown by something else in the meantime or
 * crashed).  Call checkDaemonRunning() frequently
 * to check the status of gnunetd.
 *
 * Furthermore, note that this WILL potentially kill
 * gnunetd processes on remote machines that cannot
 * be restarted with startGNUnetDaemon!
 *
 * This function does NOT need the PID and will also
 * kill daemonized gnunetd's.
 *
 * @return OK successfully stopped, SYSERR: error
 */
int stopGNUnetDaemon(void);


/**
 * Wait until the gnunet daemon is
 * running.
 *
 * @param timeout how long to wait at most
 * @return OK if gnunetd is now running
 */
int waitForGNUnetDaemonRunning(cron_t timeout);


/**
 * Wait until the gnunet daemon (or any other CHILD process for that
 * matter) with the given PID has terminated.  Assumes that
 * the daemon was started with startGNUnetDaemon in no-daemonize mode.
 * On arbitrary PIDs, this function may fail unexpectedly.
 *
 * @return YES if gnunetd shutdown with
 *  return value 0, SYSERR if waitpid
 *  failed, NO if gnunetd shutdown with
 *  some error
 */
int waitForGNUnetDaemonTermination(int pid);

/**
 * @brief Terminate a process
 * @return YES on success, NO otherwise
 */
int termProcess(int pid);

/* ifndef GNUNET_UTIL_H */
#endif
/* end of gnunet_util.h */

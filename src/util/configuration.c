/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file util/configuration.c
 * @brief high-level configuration managment (with command-line overrides)
 * @author Christian Grothoff
 * @author Gerd Knorr <kraxel@bytesex.org> 
 * 
 * Configuration file parsing, taken from xawtv (GPL).
 *
 * This file provides code to parse a configuration file and access
 * the data stored in it. It also provides methods to override options
 * which can be used to add command-line options to the configuration
 * API.
 */

#include "gnunet_util.h"
#include "platform.h"

struct CFG_ENTRIES {
  int  ent_count;
  char **ent_names;
  char **ent_values;
};

struct CFG_SECTIONS {
  int                 sec_count;
  char                **sec_names;
  struct CFG_ENTRIES  **sec_entries;
};

static struct CFG_SECTIONS * c = NULL;

#define ALLOC_SIZE 16


static struct CFG_SECTIONS * cfg_init_sections(void) {
  struct CFG_SECTIONS *c;
  c = MALLOC(sizeof(struct CFG_SECTIONS));
  memset(c,
	 0,
	 sizeof(struct CFG_SECTIONS));
  c->sec_names   = MALLOC(ALLOC_SIZE*sizeof(char*));
  c->sec_entries = MALLOC(ALLOC_SIZE*sizeof(struct CFG_ENTRIES*));
  return c;
}

static struct CFG_ENTRIES * cfg_init_entries() {
  struct CFG_ENTRIES *e;
  e = MALLOC(sizeof(struct CFG_ENTRIES));
  memset(e,
	 0,
	 sizeof(struct CFG_ENTRIES));
  e->ent_names  = MALLOC(ALLOC_SIZE*sizeof(char*));
  e->ent_values = MALLOC(ALLOC_SIZE*sizeof(char*));
  return e;
}

static struct CFG_ENTRIES * cfg_find_section(struct CFG_SECTIONS *c, 
					     const char * name) {
  struct CFG_ENTRIES * e;
  int i;
  
  for (i=0; i<c->sec_count; i++)
    if (0 == strcasecmp(c->sec_names[i], name))
      return c->sec_entries[i];
  
  /* 404 not found => create a new one */
  if ((c->sec_count % ALLOC_SIZE) == (ALLOC_SIZE-1)) {
    i = c->sec_count+1;
    GROW(c->sec_names,
	 i,
	 i+ALLOC_SIZE);
    i = c->sec_count+1;
    GROW(c->sec_entries,
	 i,
	 i+ALLOC_SIZE);
  }
  e = cfg_init_entries();
  c->sec_names[c->sec_count]   = STRDUP(name);
  c->sec_entries[c->sec_count] = e;
  c->sec_count++;    
  return e;
}

static void cfg_set_entry(struct CFG_ENTRIES * e, 
			  const char * name, 
			  const char * value) {
  int i;
  
  for (i=0; i<e->ent_count; i++)
    if (0 == strcasecmp(e->ent_names[i],
			name))
      break;
  if (i == e->ent_count) {
    /* 404 not found => create a new one */
    if ((e->ent_count % ALLOC_SIZE) == (ALLOC_SIZE-1)) {
      /* not enough space, grow first */
      i = e->ent_count+1;
      GROW(e->ent_names,
	   i,
	   i+ALLOC_SIZE);
      i = e->ent_count+1;
      GROW(e->ent_values,
	   i,
	   i+ALLOC_SIZE);
    }
    i = e->ent_count;
    e->ent_count++;    
  } else {
    /* free old values, will be replaced! */
    FREENONNULL(e->ent_names[i]);
    FREENONNULL(e->ent_values[i]);
  }      
  e->ent_names[i]  = STRDUP(name);
  e->ent_values[i] = STRDUP(value);
}

static int cfg_parse_file(char *filename) {
  struct CFG_ENTRIES * e = NULL;
  char line[256],tag[64],value[192];
  FILE *fp;
  int nr;
  int i;
  int emptyline;
  
  if (NULL == c)
    c = cfg_init_sections();
  if (NULL == (fp = FOPEN(filename,"r")))
    return -1;
  
  memset(line, 
	 0, 
	 256);
  
  nr = 0;
  while (NULL != fgets(line,255,fp)) {
    nr++;
    for (i=0;i<255;i++) {
      if (line[i] == '\t')
	line[i] = ' ';
    }
    emptyline=1;
    for (i=0;(i<255 && line[i] != 0);i++) {
      if (line[i] != ' ' && line[i] != '\n' && line[i] != '\r')
	emptyline=0;
    }
    if (emptyline == 1)
      continue;
    if (line[0] == '\n' || line[0] == '#' || line[0] == '%' ||
	line[0] == '\r')
      continue;
    for (i=strlen(line)-2 ; 
	 (i>=0) && (line[i] == ' ' || line[i] == '\t' ) ;
	 i--)
      line[i] = 0;
    if (1 == sscanf(line, "@INLINE@ %191[^\n]", value) ) {
      char * expanded = expandFileName(value);
      LOG(LOG_DEBUG,
	  _("inlining configration file '%s'\n"),
	  expanded);
      if (cfg_parse_file(expanded) != 0)
	LOG(LOG_WARNING,
	    _("Could not parse configuration file '%s'.\n"),
	    value);
    } else if (1 == sscanf(line,"[%99[^]]]", value)) {
      /* [section] */
      e = cfg_find_section(c,value);
    } else if (2 == sscanf(line," %63[^= ] = %191[^\n]",tag,value)) {
      /* foo = bar */
      if (NULL == e) /* no section defined so far: put in "global" section (change by CG) */
	e = cfg_find_section(c, "");  
      i=0;
      if (value[0] == '"') {
	i=1;
	while ( (value[i] != '\0') && 
		(value[i] != '"') )
	  i++;
	if (value[i] == '"') {
	  value[i] = '\0';
	  i=1;
	} else
	  i=0;
      }
#ifdef MINGW
      /* Strip LF */
      nr = strlen(value) - 1;
      if (nr >= 0 && value[nr] == '\r')
	value[nr] = 0;
#endif
      cfg_set_entry(e, tag, &value[i]);
      
    } else {
      /* Huh ? */
      LOG(LOG_ERROR,
	  _("Syntax error in configuration file '%s' at line %d.\n"),
	  filename, nr);
    }
  }
  fclose(fp);
  return 0;
}

/* ------------------------------------------------------------------------ */

static char * cfg_get_str(const char * sec, 
			  const char * ent) {
  struct CFG_ENTRIES * e = NULL;
  int i;
  
  for (i = 0; i < c->sec_count; i++)
    if (0 == strcasecmp(c->sec_names[i],sec))
      e = c->sec_entries[i];
  if (NULL == e)
    return NULL;
  for (i = 0; i < e->ent_count; i++)
    if (0 == strcasecmp(e->ent_names[i],ent)) {
      return e->ent_values[i];
    }
  return NULL;
}

static int cfg_get_signed_int(const char *sec, 
			      const char *ent) {
  char *val;

  val = cfg_get_str(sec, ent);    
  if (NULL == val)
    return 0;
  return atoi(val);
}

static void doneParseConfig() {
  int i;
  int j;

  if (c == NULL)
    return;	      
  for (i=0;i<c->sec_count;i++) {
    if (c->sec_entries[i] != NULL) {
      for (j=0;j<c->sec_entries[i]->ent_count;j++) {
	FREENONNULL(c->sec_entries[i]->ent_names[j]);
	FREENONNULL(c->sec_entries[i]->ent_values[j]);
      }    
      FREENONNULL(c->sec_entries[i]->ent_names);
      FREENONNULL(c->sec_entries[i]->ent_values);
    }
    FREENONNULL(c->sec_entries[i]);
    FREENONNULL(c->sec_names[i]);
  }
  FREENONNULL(c->sec_entries);
  FREENONNULL(c->sec_names);
  FREENONNULL(c);
  c = NULL;
}



/**
 * Type for user-defined configuration entries.
 */
typedef struct UserConfStruct {
  char * section;
  char * option;
  char * stringValue;
  unsigned int intValue;
  struct UserConfStruct * next;
} UserConf;

/**
 * GNUnet configuration (OpenSSL datastructure)
 */
static int parseConfigInit = NO;

/**
 * The filename of the config (for re-reading!)
 */
static char * configuration_filename = NULL;

/**
 * Lock to access configuration (we may receive an
 * update signal at any time!)
 */
static Mutex configLock;

/**
 * List of run-time options (not in the configuration
 * file, but for example from the command line).
 */
static UserConf * userconfig = NULL;

/**
 * The command line strings (rest)
 */ 
static char ** values;
static int valuesCount;

/**
 * Expand an expression of the form
 * "$FOO/BAR" to "DIRECTORY/BAR" where
 * either in the current section or
 * globally FOO is set to DIRECTORY.
 */
static char * expandDollar(const char * section,
			   char * orig) {
  int i;
  char * prefix;
  char * result;
  
  i=0;
  while ( (orig[i] != '/') &&
      (orig[i] != '\\') &&
	  (orig[i] != '\0') )
    i++;
  if (orig[i] == '\0')
    return orig;
  orig[i] = '\0';
  prefix = getConfigurationString(section,
				  &orig[1]);
  if (prefix == NULL)
    prefix = getConfigurationString("", &orig[1]);
  if (prefix == NULL) {
    orig[i] = DIR_SEPARATOR;
    return orig;
  }
  result = MALLOC(strlen(prefix) + 
		  strlen(&orig[i+1]) + 2);
  strcpy(result, prefix);
#ifndef MINGW
  strcat(result, "/");
#else
  strcat(result, "\\");
#endif
  strcat(result, &orig[i+1]);
  FREE(prefix);
  FREE(orig);
  return result;
}

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
		   const char * errMsg) {
  char * fn;  
  char * fnExpand;

  fn = getConfigurationString(section, 
			      option);
  if (fn == NULL) {
    if (errMsg == NULL)
      return NULL;
    else
      errexit(errMsg,
	      section,
	      option);
  }
  fnExpand = expandFileName(fn);   
  FREE(fn);
  return fnExpand;
}

void generate_gnunetd_conf(FILE * f);
void generate_gnunet_conf(FILE * f);

/**
 * Read the configuration file.  The previous configuration will be
 * discarded if this method is invoked twice.
 */
void readConfiguration() {
  /* getFileName aquires the mutex, so we better do this first */
  char * cfgName;
  char * expCfgName;

  cfgName = getConfigurationString("FILES",
				   "gnunet.conf");
  if (cfgName == NULL) {
    if (testConfigurationString("GNUNETD",
				"_MAGIC_",
				"YES")) {
      expCfgName = getenv("GNUNETD_CONFIG");
      if (expCfgName == NULL)
	expCfgName = DEFAULT_DAEMON_CONFIG_FILE;
    } else {
      expCfgName = getenv("GNUNET_CONFIG");
      if (expCfgName == NULL)
	expCfgName = DEFAULT_CLIENT_CONFIG_FILE;
    }
    expCfgName = expandFileName(expCfgName);
    setConfigurationString("FILES",
			   "gnunet.conf",
			   expCfgName);
  } else {
    expCfgName = expandFileName(cfgName);
  }
  if (0 == assertIsFile(expCfgName)) {
    FILE * f;
    char * c;
    int p;

    /* create directory (~/.gnunet/) */
    c = STRDUP(expCfgName);
    p = strlen(c);
    while ( (p > 0) && (c[p] != '/') )
      p--;
    c[p] = '\0';
    mkdirp(c);
    FREE(c);
    /* try generating a configuration file */
    LOG(LOG_WARNING,
	_("Configuration file '%s' not found. I will try to create the default configuration file at that location.\n"),
	expCfgName);
    f = FOPEN(expCfgName,
	      "a+");
    if (f != NULL) {
      if (testConfigurationString("GNUNETD",
				  "_MAGIC_",
				  "YES")) {
	generate_gnunetd_conf(f);
      } else {
	generate_gnunet_conf(f);
      }	
      fclose(f);
    }
  }
  if (0 == assertIsFile(expCfgName)) 
    errexit(_("Cannot open configuration file '%s'\n"),
	    expCfgName); 
  FREENONNULL(cfgName);

  FREENONNULL(setConfigurationString("FILES",
				     "gnunet.conf",
				     expCfgName));
  MUTEX_LOCK(&configLock);
  FREENONNULL(configuration_filename);
  configuration_filename = expCfgName;
  
  if (parseConfigInit == YES) {
    doneParseConfig();
    parseConfigInit = NO;
  }
  if (0 != cfg_parse_file(configuration_filename))
    errexit("Failed to parse configuration file '%s'.\n",
	    configuration_filename);
  parseConfigInit = YES;
  MUTEX_UNLOCK(&configLock);
}

static NotifyConfigurationUpdateCallback * cbl = NULL;
static int cbCnt = 0;

/**
 * Register a callback that is called when the configuration
 * changes.  The API guarantees that the call is made either
 * as a cron-job or while cron is suspended, so it is safe
 * to edit (delete) cron jobs in the callback.
 */
void registerConfigurationUpdateCallback(NotifyConfigurationUpdateCallback cb) {
  MUTEX_LOCK(&configLock);
  GROW(cbl,
       cbCnt,
       cbCnt+1);
  cbl[cbCnt-1] = cb;
  MUTEX_UNLOCK(&configLock);
}

void unregisterConfigurationUpdateCallback(NotifyConfigurationUpdateCallback cb) {
  int i;
  
  MUTEX_LOCK(&configLock);
  for (i=0;i<cbCnt;i++)
    if (cbl[i] == cb)
      break;
  GNUNET_ASSERT(i<cbCnt);
  cbl[i] = cbl[cbCnt-1];
  GROW(cbl,
       cbCnt,
       cbCnt-1);
  MUTEX_UNLOCK(&configLock);
}

static void triggerConfigRefreshHelper(void * arg) {
  int i;
  MUTEX_LOCK(&configLock);
  for (i=0;i<cbCnt;i++)
    cbl[i]();
  MUTEX_UNLOCK(&configLock);
}

void triggerGlobalConfigurationRefresh() {
  /* guarantee (!) that this is ALWAYS done
     inside of a cron-job! */
  addCronJob(&triggerConfigRefreshHelper,
	     0, 0, NULL);
}

/**
 * This method must be called first! It reads
 * the config file and makes everything else
 * possible.
 */
void initConfiguration() {
  MUTEX_CREATE_RECURSIVE(&configLock);
}

/**
 * This method may be called at last to clean up.
 * Afterwards everything but initConfiguration will result
 * in errors...
 */
void doneConfiguration() {
  parseConfigInit = NO;
  doneParseConfig();
  FREENONNULL(configuration_filename);
  configuration_filename = NULL;
  MUTEX_DESTROY(&configLock);
  while (userconfig != NULL) {
    UserConf * tmp = userconfig;
    userconfig = userconfig->next;
    FREENONNULL(tmp->section);
    FREENONNULL(tmp->option);
    FREENONNULL(tmp->stringValue);
    FREE(tmp);
  }
}


/**
 * Obtain a string from the configuration.
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 * @return a freshly allocated string, caller must free!
 *   Note that the result can be NULL if the option is not set.
 */
char * getConfigurationString(const char * section,
			      const char * option) {
  UserConf * pos;
  char * retval;

  GNUNET_ASSERT( (section != NULL) && (option != NULL) );
  MUTEX_LOCK(&configLock);
  pos = userconfig;
  while (pos != NULL) {
    if ( (strcmp(section, pos->section) == 0) &&
	 (strcmp(option, pos->option) == 0) ) {
      if (pos->stringValue != NULL)
	retval = STRDUP(pos->stringValue);
      else
	retval = NULL; 
      MUTEX_UNLOCK(&configLock);
      if (retval != NULL)
	if (retval[0] == '$') {
	  retval = expandDollar(section,
				retval);
	}
      return retval;
    }
    pos = pos->next;
  }
  retval = NULL;
  if (parseConfigInit == YES)
    retval = cfg_get_str(section, option);
  if (retval != NULL)
    retval = STRDUP(retval);  
  MUTEX_UNLOCK(&configLock);
  if (retval != NULL)
    if (retval[0] == '$') 
      retval = expandDollar(section, retval);    
  return retval;
}

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
			    const char * value) {
  char * c;

  GNUNET_ASSERT( (section != NULL) && (option != NULL) );
  c = getConfigurationString(section, option);
  if (c == NULL) {
    if (value == NULL)
      return YES;
    else
      return NO;
  } else {
    int ret;
    if (value == NULL) {
      FREE(c);
      return NO;
    }
    if (0 == strcmp(c, value))
      ret = YES;
    else
      ret = NO;
    FREE(c);
    return ret;
  }
}

/**
 * Obtain an int from the configuration.
 *
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 * @return 0 if no option is specified
 */
unsigned int getConfigurationInt(const char * section,
				 const char * option) {
  UserConf * pos;
  unsigned int retval;

  GNUNET_ASSERT( (section != NULL) && (option != NULL) );
  MUTEX_LOCK(&configLock);
  pos = userconfig;
  while (pos != NULL) {
    if ( (strcmp(section, pos->section) == 0) &&
	 (strcmp(option, pos->option) == 0) ) {
      retval = pos->intValue;
      MUTEX_UNLOCK(&configLock);
      return retval;
    }
    pos = pos->next;
  }
  retval = 0;
  if (parseConfigInit == YES) 
    retval = cfg_get_signed_int(section, option);
  MUTEX_UNLOCK(&configLock);
  return retval;
}

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
			      const char * value) {
  UserConf * pos;
  UserConf * prev; 
  char * res;

  GNUNET_ASSERT( (section != NULL) && (option != NULL) );
  MUTEX_LOCK(&configLock);
  prev = NULL;
  pos = userconfig;
  while (pos != NULL) {
    if ( (strcmp(section, pos->section) == 0) &&
	 (strcmp(option, pos->option) == 0) ) {
      res = pos->stringValue;
      if (value != NULL)
	pos->stringValue = STRDUP(value);
      else
	pos->stringValue = NULL;
      MUTEX_UNLOCK(&configLock);
      return res;
    }
    prev = pos;
    pos = pos->next;
  }
  if (prev == NULL) {
    userconfig = MALLOC(sizeof(UserConf));
    pos = userconfig;
  } else {
    prev->next = MALLOC(sizeof(UserConf));
    pos = prev->next;
  }
  pos->section = STRDUP(section);
  pos->option = STRDUP(option);
  if (value != NULL)
    pos->stringValue = STRDUP(value);
  else 
    pos->stringValue = NULL;
  pos->intValue = 0;
  pos->next = NULL;
  res = NULL;
  if (parseConfigInit == YES) {
    res = cfg_get_str(section, option);
    if (res != NULL)
      res = STRDUP(res);
  }
  MUTEX_UNLOCK(&configLock);
  return res;    
}

/**
 * Set an option.
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 * @param value the value to use
 * @return the previous value (or 0 if none)
 */
unsigned int setConfigurationInt(const char * section,
				 const char * option,
				 const unsigned int value) {
  UserConf * pos;
  UserConf * prev; 
  unsigned int res;

  GNUNET_ASSERT( (section != NULL) && (option != NULL) );
  MUTEX_LOCK(&configLock);
  prev = NULL;
  pos = userconfig;
  while (pos != NULL) {
    if ( (strcmp(section, pos->section) == 0) &&
	 (strcmp(option, pos->option) == 0) ) {
      res = pos->intValue;
      pos->intValue = value;
      MUTEX_UNLOCK(&configLock);
      return res;
    }
    prev = pos;
    pos = pos->next;
  }
  if (prev == NULL) {
    userconfig = MALLOC(sizeof(UserConf));
    pos = userconfig;
  } else {
    prev->next = MALLOC(sizeof(UserConf));
    pos = prev->next;
  }
  pos->section = STRDUP(section);
  pos->option = STRDUP(option);
  pos->stringValue = NULL;
  pos->intValue = value;
  pos->next = NULL;
  res = 0;
  if (parseConfigInit == YES)
    res = cfg_get_signed_int(section, option);
  MUTEX_UNLOCK(&configLock);
  return res; 
}

/**
 * Get the command line strings (the ones remaining after getopt-style
 * parsing).
 *
 * @param value the values
 + @return the number of values
 */
int getConfigurationStringList(char *** value) {
  char ** cpy;
  int i;

  cpy = MALLOC(sizeof(char*) * valuesCount);
  for (i=0;i<valuesCount;i++)
    cpy[i] = STRDUP(values[i]);
  *value = cpy;
  return valuesCount;
}

/**
 * Set the list of command line options (remainder after getopt style
 * parsing).
 *
 * @param value the values 
 + @param count the number of values
 */
void setConfigurationStringList(char ** value,
				int count) {
  values = value;
  valuesCount = count;
}

/* end of configuration.c */

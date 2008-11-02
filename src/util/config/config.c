/*
     This file is part of GNUnet.
     (C) 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file src/util/config/config.c
 * @brief configuration management
 *
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"

/**
 * @brief configuration entry
 */
typedef struct GNUNET_GC_Entry
{

  /**
   * key for this entry
   */
  char *key;

  /**
   * current, commited value
   */
  char *val;

  /**
   * non-null during uncommited update
   */
  char *dirty_val;
} GNUNET_GC_Entry;

/**
 * @brief configuration section
 */
typedef struct GNUNET_GC_Section
{

  /**
   * name of the section
   */
  char *name;

  /**
   * number of entries in section
   */
  unsigned int size;

  /**
   * entries in the section
   */
  GNUNET_GC_Entry *entries;
} GNUNET_GC_Section;

/**
 * @brief GNUNET_GC_ChangeListener and context
 */
typedef struct GNUNET_GC_Listener
{

  /**
   * Callback.
   */
  GNUNET_GC_ChangeListener listener;

  /**
   * Context for callback.
   */
  void *ctx;
} GNUNET_GC_Listener;

/**
 * @brief configuration data
 */
typedef struct GNUNET_GC_Configuration
{

  /**
   * Lock to access the data.
   */
  struct GNUNET_Mutex *lock;

  /**
   * Context for logging errors, maybe NULL.
   */
  struct GNUNET_GE_Context *ectx;

  /**
   * Modification indication since last save
   * GNUNET_NO if clean, GNUNET_YES if dirty,
   * GNUNET_SYSERR on error (i.e. last save failed)
   */
  int dirty;

  /**
   * How many sections do we have?
   */
  unsigned int ssize;

  /**
   * Array with "ssize" entries.
   */
  GNUNET_GC_Section *sections;

  /**
   * How many listeners do we have?
   */
  unsigned int lsize;

  /**
   * Array with "lsize" entries.
   */
  GNUNET_GC_Listener *listeners;

} GNUNET_GC_Configuration;

void
GNUNET_GC_free (struct GNUNET_GC_Configuration *cfg)
{
  GNUNET_GC_Section *sec;
  GNUNET_GC_Entry *e;
  int i;
  int j;

  for (i = 0; i < cfg->ssize; i++)
    {
      sec = &cfg->sections[i];
      for (j = 0; j < sec->size; j++)
        {
          e = &sec->entries[j];
          GNUNET_free (e->key);
          GNUNET_free_non_null (e->val);
          GNUNET_GE_ASSERT (cfg->ectx, e->dirty_val == NULL);
        }
      GNUNET_array_grow (sec->entries, sec->size, 0);
      GNUNET_free (sec->name);
    }
  GNUNET_array_grow (cfg->sections, cfg->ssize, 0);
  GNUNET_GE_ASSERT (cfg->ectx, cfg->listeners == 0);
  GNUNET_mutex_destroy (cfg->lock);
  GNUNET_free (cfg);
}

void
GNUNET_GC_set_error_context (struct GNUNET_GC_Configuration *cfg,
                             struct GNUNET_GE_Context *ectx)
{
  cfg->ectx = ectx;
}

int
GNUNET_GC_parse_configuration (struct GNUNET_GC_Configuration *cfg,
                               const char *filename)
{
  int dirty;
  char line[256];
  char tag[64];
  char value[192];
  FILE *fp;
  int nr;
  int i;
  int emptyline;
  int ret;
  char *section;
  char *fn;

  fn = GNUNET_expand_file_name (NULL, filename);
  GNUNET_mutex_lock (cfg->lock);
  dirty = cfg->dirty;           /* back up value! */
  if (NULL == (fp = FOPEN (fn, "r")))
    {
      GNUNET_GE_LOG_STRERROR_FILE (cfg->ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_USER |
                                   GNUNET_GE_IMMEDIATE | GNUNET_GE_BULK |
                                   GNUNET_GE_REQUEST, "fopen", fn);
      GNUNET_mutex_unlock (cfg->lock);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fn);
  ret = 0;
  section = GNUNET_strdup ("");
  memset (line, 0, 256);
  nr = 0;
  while (NULL != fgets (line, 255, fp))
    {
      nr++;
      for (i = 0; i < 255; i++)
        if (line[i] == '\t')
          line[i] = ' ';
      if (line[0] == '\n' || line[0] == '#' || line[0] == '%' ||
          line[0] == '\r')
        continue;
      emptyline = 1;
      for (i = 0; (i < 255 && line[i] != 0); i++)
        if (line[i] != ' ' && line[i] != '\n' && line[i] != '\r')
          emptyline = 0;
      if (emptyline == 1)
        continue;
      /* remove tailing whitespace */
      for (i = strlen (line) - 1; (i >= 0) && (isspace (line[i])); i--)
        line[i] = '\0';
      if (1 == sscanf (line, "@INLINE@ %191[^\n]", value))
        {
          /* @INLINE@ value */
          char *expanded = GNUNET_expand_file_name (cfg->ectx,
                                                    value);
          if (0 != GNUNET_GC_parse_configuration (cfg, expanded))
            ret = GNUNET_SYSERR;        /* failed to parse included config */
        }
      else if (1 == sscanf (line, "[%99[^]]]", value))
        {
          /* [value] */
          GNUNET_free (section);
          section = GNUNET_strdup (value);
        }
      else if (2 == sscanf (line, " %63[^= ] = %191[^\n]", tag, value))
        {
          /* tag = value */
          /* Strip LF */
          i = strlen (value) - 1;
          while ((i >= 0) && (isspace (value[i])))
            value[i--] = '\0';
          /* remove quotes */
          i = 0;
          if (value[0] == '"')
            {
              i = 1;
              while ((value[i] != '\0') && (value[i] != '"'))
                i++;
              if (value[i] == '"')
                {
                  value[i] = '\0';
                  i = 1;
                }
              else
                i = 0;
            }
          /* first check if we have this value already;
             this could happen if the value was changed
             using a command-line option; only set it
             if we do not have a value already... */
          if ((GNUNET_NO == GNUNET_GC_have_configuration_value (cfg,
                                                                section,
                                                                tag)) &&
              (0 != GNUNET_GC_set_configuration_value_string (cfg,
                                                              cfg->ectx,
                                                              section,
                                                              tag,
                                                              &value[i])))
            ret = GNUNET_SYSERR;        /* could not set value */
        }
      else if (1 == sscanf (line, " %63[^= ] =[^\n]", tag))
        {
          /* tag = */
          /* first check if we have this value already;
             this could happen if the value was changed
             using a command-line option; only set it
             if we do not have a value already... */
          if ((GNUNET_NO == GNUNET_GC_have_configuration_value (cfg,
                                                                section,
                                                                tag)) &&
              (0 != GNUNET_GC_set_configuration_value_string (cfg,
                                                              cfg->ectx,
                                                              section, tag,
                                                              "")))
            ret = GNUNET_SYSERR;        /* could not set value */
        }
      else
        {
          /* parse error */
          GNUNET_GE_LOG (cfg->ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_USER |
                         GNUNET_GE_IMMEDIATE | GNUNET_GE_BULK,
                         _
                         ("Syntax error in configuration file `%s' at line %d.\n"),
                         filename, nr);
          ret = GNUNET_SYSERR;
          break;
        }
    }
  if (0 != fclose (fp))
    {
      GNUNET_GE_LOG_STRERROR_FILE (cfg->ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE |
                                   GNUNET_GE_BULK | GNUNET_GE_REQUEST,
                                   "fclose", filename);
      ret = GNUNET_SYSERR;
    }
  /* restore dirty flag - anything we set in the meantime
     came from disk */
  cfg->dirty = dirty;
  GNUNET_mutex_unlock (cfg->lock);
  GNUNET_free (section);
  return ret;
}

int
GNUNET_GC_test_dirty (struct GNUNET_GC_Configuration *cfg)
{
  return cfg->dirty;
}

int
GNUNET_GC_write_configuration (struct GNUNET_GC_Configuration *data,
                               const char *filename)
{
  GNUNET_GC_Section *sec;
  GNUNET_GC_Entry *e;
  int i;
  int j;
  FILE *fp;
  int error;
  int ret;
  char *fn;
  char *val;
  char *pos;

  fn = GNUNET_expand_file_name (NULL, filename);
  GNUNET_disk_directory_create_for_file (NULL, fn);
  if (NULL == (fp = FOPEN (fn, "w")))
    {
      GNUNET_GE_LOG_STRERROR_FILE (data->ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_USER |
                                   GNUNET_GE_IMMEDIATE, "fopen", fn);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fn);
  error = 0;
  ret = 0;
  GNUNET_mutex_lock (data->lock);
  for (i = 0; i < data->ssize; i++)
    {
      sec = &data->sections[i];
      if (0 > fprintf (fp, "[%s]\n", sec->name))
        {
          error = 1;
          break;
        }
      for (j = 0; j < sec->size; j++)
        {
          e = &sec->entries[j];
          GNUNET_GE_ASSERT (data->ectx, e->dirty_val == NULL);
          if (e->val != NULL)
            {
              val = GNUNET_malloc (strlen (e->val) * 2 + 1);
              strcpy (val, e->val);
              while (NULL != (pos = strstr (val, "\n")))
                {
                  memmove (&pos[2], &pos[1], strlen (&pos[1]));
                  pos[0] = '\\';
                  pos[1] = 'n';
                }
              if (0 > fprintf (fp, "%s = %s\n", e->key, val))
                {
                  error = 1;
                  GNUNET_free (val);
                  break;
                }
              GNUNET_free (val);
            }
        }
      if (error != 0)
        break;
      if (0 > fprintf (fp, "\n"))
        {
          error = 1;
          break;
        }
    }
  if (error != 0)
    GNUNET_GE_LOG_STRERROR_FILE (data->ectx,
                                 GNUNET_GE_ERROR | GNUNET_GE_USER |
                                 GNUNET_GE_IMMEDIATE | GNUNET_GE_BULK |
                                 GNUNET_GE_REQUEST, "fprintf", filename);
  if (0 != fclose (fp))
    {
      GNUNET_GE_LOG_STRERROR_FILE (data->ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE |
                                   GNUNET_GE_BULK | GNUNET_GE_REQUEST,
                                   "fclose", filename);
      error = 1;
    }
  if (error == 0)
    {
      ret = 0;
      data->dirty = GNUNET_NO;  /* last write succeeded */
    }
  else
    {
      ret = GNUNET_SYSERR;
      data->dirty = GNUNET_SYSERR;      /* last write failed */
    }
  GNUNET_mutex_unlock (data->lock);
  return ret;
}

/**
 * Call only with lock held!
 */
static GNUNET_GC_Section *
findSection (GNUNET_GC_Configuration * data, const char *section)
{
  int i;
  for (i = data->ssize - 1; i >= 0; i--)
    if (0 == strcmp (section, data->sections[i].name))
      return &data->sections[i];
  return NULL;
}

/**
 * Call only with lock held!
 */
static GNUNET_GC_Entry *
findEntry (GNUNET_GC_Configuration * data, const char *section,
           const char *key)
{
  int i;
  GNUNET_GC_Section *sec;

  sec = findSection (data, section);
  if (sec == NULL)
    return NULL;
  for (i = sec->size - 1; i >= 0; i--)
    if (0 == strcmp (key, sec->entries[i].key))
      return &sec->entries[i];
  return NULL;
}

int
GNUNET_GC_set_configuration_value_string (struct GNUNET_GC_Configuration
                                          *data,
                                          struct GNUNET_GE_Context *ectx,
                                          const char *section,
                                          const char *option,
                                          const char *value)
{
  GNUNET_GC_Section *sec;
  GNUNET_GC_Section nsec;
  GNUNET_GC_Entry *e;
  GNUNET_GC_Entry ne;
  int ret;
  int i;

  GNUNET_mutex_lock (data->lock);
  e = findEntry (data, section, option);
  if (e == NULL)
    {
      sec = findSection (data, section);
      if (sec == NULL)
        {
          nsec.name = GNUNET_strdup (section);
          nsec.size = 0;
          nsec.entries = NULL;
          GNUNET_array_append (data->sections, data->ssize, nsec);
          sec = findSection (data, section);
        }
      ne.key = GNUNET_strdup (option);
      ne.val = NULL;
      ne.dirty_val = NULL;
      GNUNET_array_append (sec->entries, sec->size, ne);
      e = findEntry (data, section, option);
    }
  if (e->dirty_val != NULL)
    {
      if (0 == strcmp (e->dirty_val, value))
        {
          ret = 0;
        }
      else
        {
          /* recursive update to different value -- not allowed! */
          GNUNET_GE_BREAK (ectx, 0);
          ret = GNUNET_SYSERR;
        }
    }
  else
    {
      e->dirty_val = GNUNET_strdup (value);
      i = data->lsize - 1;
      while (i >= 0)
        {
          if (0 != data->listeners[i].listener (data->listeners[i].ctx,
                                                data, ectx, section, option))
            break;              /* update refused */
          i--;
          e = findEntry (data, section, option);        /* side-effects of callback are possible! */
        }
      e = findEntry (data, section, option);    /* side-effects of callback are possible! */
      if (i >= 0)
        {
          /* update refused, revert! */
          GNUNET_free (e->dirty_val);
          e->dirty_val = NULL;
          i++;                  /* the callback that refused does not need refreshing */
          while (i < data->lsize)
            {
              if (0 != data->listeners[i].listener (data->listeners[i].ctx,
                                                    data,
                                                    ectx, section, option))
                GNUNET_GE_ASSERT (ectx, 0);     /* refused the refusal!? */
              e = findEntry (data, section, option);    /* side-effects of callback are possible! */
              i++;
            }
          ret = GNUNET_SYSERR;  /* error -- update refused */
        }
      else
        {
          /* all confirmed, commit! */
          if ((e->val == NULL) || (0 != strcmp (e->val, e->dirty_val)))
            data->dirty = GNUNET_YES;
          GNUNET_free_non_null (e->val);
          e->val = e->dirty_val;
          e->dirty_val = NULL;
          ret = 0;
        }
    }
  if (ret == GNUNET_SYSERR)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_USER | GNUNET_GE_BULK | GNUNET_GE_WARNING,
                   ("Setting option `%s' in section `%s' to value `%s' was refused.\n"),
                   option, section, value);
  GNUNET_mutex_unlock (data->lock);
  return ret;
}

int
GNUNET_GC_set_configuration_value_number (struct GNUNET_GC_Configuration *cfg,
                                          struct GNUNET_GE_Context *ectx,
                                          const char *section,
                                          const char *option,
                                          unsigned long long number)
{
  char s[64];
  GNUNET_snprintf (s, 64, "%llu", number);
  return GNUNET_GC_set_configuration_value_string (cfg, ectx, section, option,
                                                   s);
}

int
GNUNET_GC_get_configuration_value_number (struct GNUNET_GC_Configuration *cfg,
                                          const char *section,
                                          const char *option,
                                          unsigned long long min,
                                          unsigned long long max,
                                          unsigned long long def,
                                          unsigned long long *number)
{
  GNUNET_GC_Entry *e;
  const char *val;
  int ret;

  GNUNET_mutex_lock (cfg->lock);
  e = findEntry (cfg, section, option);
  if (e != NULL)
    {
      val = (e->dirty_val != NULL) ? e->dirty_val : e->val;
      if (1 == SSCANF (val, "%llu", number))
        {
          if ((*number >= min) && (*number <= max))
            {
              ret = GNUNET_NO;
            }
          else
            {
              GNUNET_GE_LOG (cfg->ectx,
                             GNUNET_GE_ERROR | GNUNET_GE_USER |
                             GNUNET_GE_BULK,
                             _("Configuration value '%llu' for '%s' "
                               "in section '%s' is out of legal bounds [%llu,%llu]\n"),
                             *number, option, section, min, max);
              ret = GNUNET_SYSERR;
            }
        }
      else
        {
          GNUNET_GE_LOG (cfg->ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Configuration value '%s' for '%s'"
                           " in section '%s' should be a number\n"),
                         val, option, section, min, max);
          ret = GNUNET_SYSERR;
        }
    }
  else
    {
      *number = def;
      GNUNET_GC_set_configuration_value_number (cfg,
                                                cfg->ectx, section, option,
                                                def);
      ret = GNUNET_YES;         /* default */
    }
  GNUNET_mutex_unlock (cfg->lock);
  return ret;
}

int
GNUNET_GC_get_configuration_value_string (struct GNUNET_GC_Configuration *cfg,
                                          const char *section,
                                          const char *option,
                                          const char *def, char **value)
{
  GNUNET_GC_Entry *e;
  const char *val;
  int ret;

  GNUNET_mutex_lock (cfg->lock);
  e = findEntry (cfg, section, option);
  if (e != NULL)
    {
      val = (e->dirty_val != NULL) ? e->dirty_val : e->val;
      *value = GNUNET_strdup (val);
      ret = GNUNET_NO;
    }
  else
    {
      if (def == NULL)
        {
          GNUNET_mutex_unlock (cfg->lock);
          GNUNET_GE_LOG (cfg->ectx,
                         GNUNET_GE_USER | GNUNET_GE_IMMEDIATE |
                         GNUNET_GE_ERROR,
                         "Configuration value for option `%s' in section `%s' required.\n",
                         option, section);
          return GNUNET_SYSERR;
        }
      *value = GNUNET_strdup (def);
      GNUNET_GC_set_configuration_value_string (cfg,
                                                cfg->ectx, section, option,
                                                def);
      ret = GNUNET_YES;         /* default */
    }
  GNUNET_mutex_unlock (cfg->lock);
  return ret;
}

int
GNUNET_GC_get_configuration_value_choice (struct GNUNET_GC_Configuration *cfg,
                                          const char *section,
                                          const char *option,
                                          const char **choices,
                                          const char *def, const char **value)
{
  GNUNET_GC_Entry *e;
  const char *val;
  int i;
  int ret;

  GNUNET_mutex_lock (cfg->lock);
  e = findEntry (cfg, section, option);
  if (e != NULL)
    {
      val = (e->dirty_val != NULL) ? e->dirty_val : e->val;
      i = 0;
      while (choices[i] != NULL)
        {
          if (0 == strcasecmp (choices[i], val))
            break;
          i++;
        }
      if (choices[i] == NULL)
        {
          GNUNET_GE_LOG (cfg->ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Configuration value '%s' for '%s'"
                           " in section '%s' is not in set of legal choices\n"),
                         val, option, section);
          ret = GNUNET_SYSERR;
        }
      else
        {
          *value = choices[i];
          ret = GNUNET_NO;
        }
    }
  else
    {
      *value = def;
      if (def == NULL)
        ret = GNUNET_SYSERR;
      else
        ret = GNUNET_YES;       /* default */
    }
  GNUNET_mutex_unlock (cfg->lock);
  return ret;
}

/**
 * Test if we have a value for a particular option
 * @return GNUNET_YES if so, GNUNET_NO if not.
 */
int
GNUNET_GC_have_configuration_value (struct GNUNET_GC_Configuration *cfg,
                                    const char *section, const char *option)
{
  GNUNET_GC_Entry *e;
  int ret;

  GNUNET_mutex_lock (cfg->lock);
  e = findEntry (cfg, section, option);
  if (e == NULL)
    ret = GNUNET_NO;
  else
    ret = GNUNET_YES;
  GNUNET_mutex_unlock (cfg->lock);
  return ret;
}

/**
 * Expand an expression of the form "$FOO/BAR" to "DIRECTORY/BAR"
 * where either in the "PATHS" section or the environtment
 * "FOO" is set to "DIRECTORY".
 *
 * @param old string to $-expand (will be freed!)
 * @return $-expanded string
 */
char *
GNUNET_GC_configuration_expand_dollar (struct GNUNET_GC_Configuration *cfg,
                                       char *orig)
{
  int i;
  char *prefix;
  char *result;
  const char *post;

  if (orig[0] != '$')
    return orig;
  i = 0;
  while ((orig[i] != '/') && (orig[i] != '\\') && (orig[i] != '\0'))
    i++;
  if (orig[i] == '\0')
    {
      post = "";
    }
  else
    {
      orig[i] = '\0';
      post = &orig[i + 1];
    }
  prefix = NULL;
  if (GNUNET_YES ==
      GNUNET_GC_have_configuration_value (cfg, "PATHS", &orig[1]))
    {
      if (0 != GNUNET_GC_get_configuration_value_string (cfg,
                                                         "PATHS",
                                                         &orig[1], NULL,
                                                         &prefix))
        {
          GNUNET_GE_BREAK (NULL, 0);
          return orig;
        }
    }
  else
    {
      const char *env = getenv (&orig[1]);

      if (env != NULL)
        {
          prefix = GNUNET_strdup (env);
        }
      else
        {
          orig[i] = DIR_SEPARATOR;
          return orig;
        }
    }
  result = GNUNET_malloc (strlen (prefix) + strlen (post) + 2);
  strcpy (result, prefix);
  if ((strlen (prefix) == 0) ||
      (prefix[strlen (prefix) - 1] != DIR_SEPARATOR))
    strcat (result, DIR_SEPARATOR_STR);
  strcat (result, post);
  GNUNET_free (prefix);
  GNUNET_free (orig);
  return result;
}

/**
 * Get a configuration value that should be a string.
 * @param def default value (use indicated by return value;
 *        will NOT be aliased, maybe NULL)
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified and no default given
 * @return 0 on success, -1 on error, 1 for default
 */
int
GNUNET_GC_get_configuration_value_filename (struct GNUNET_GC_Configuration
                                            *data, const char *section,
                                            const char *option,
                                            const char *def, char **value)
{
  int ret;
  char *tmp;

  tmp = NULL;
  ret =
    GNUNET_GC_get_configuration_value_string (data, section, option, def,
                                              &tmp);
  if (tmp != NULL)
    {
      tmp = GNUNET_GC_configuration_expand_dollar (data, tmp);
      *value = GNUNET_expand_file_name (data->ectx, tmp);
      GNUNET_free (tmp);
    }
  else
    {
      *value = NULL;
    }
  return ret;
}

int
GNUNET_GC_set_configuration_value_choice (struct GNUNET_GC_Configuration *cfg,
                                          struct GNUNET_GE_Context *ectx,
                                          const char *section,
                                          const char *option,
                                          const char *choice)
{
  return GNUNET_GC_set_configuration_value_string (cfg, ectx, section, option,
                                                   choice);
}

int
GNUNET_GC_attach_change_listener (struct GNUNET_GC_Configuration *cfg,
                                  GNUNET_GC_ChangeListener callback,
                                  void *ctx)
{
  GNUNET_GC_Listener l;
  int i;
  int j;

  GNUNET_mutex_lock (cfg->lock);
  for (i = 0; i < cfg->ssize; i++)
    {
      GNUNET_GC_Section *s = &cfg->sections[i];
      for (j = 0; j < s->size; j++)
        {
          GNUNET_GC_Entry *e = &s->entries[j];
          if (0 != callback (ctx, cfg, cfg->ectx, s->name, e->key))
            {
              GNUNET_mutex_unlock (cfg->lock);
              return GNUNET_SYSERR;
            }
          s = &cfg->sections[i];        /* side-effects of callback are possible! */
        }
    }
  l.listener = callback;
  l.ctx = ctx;
  GNUNET_array_append (cfg->listeners, cfg->lsize, l);
  GNUNET_mutex_unlock (cfg->lock);
  return 0;
}

int
GNUNET_GC_detach_change_listener (struct GNUNET_GC_Configuration *cfg,
                                  GNUNET_GC_ChangeListener callback,
                                  void *ctx)
{
  int i;
  GNUNET_GC_Listener *l;

  GNUNET_mutex_lock (cfg->lock);
  for (i = cfg->lsize - 1; i >= 0; i--)
    {
      l = &cfg->listeners[i];
      if ((l->listener == callback) && (l->ctx == ctx))
        {
          cfg->listeners[i] = cfg->listeners[cfg->lsize - 1];
          GNUNET_array_grow (cfg->listeners, cfg->lsize, cfg->lsize - 1);
          GNUNET_mutex_unlock (cfg->lock);
          return GNUNET_OK;
        }
    }
  GNUNET_mutex_unlock (cfg->lock);
  return GNUNET_NO;
}

/**
 * Create a GNUNET_GC_Configuration.
 */
GNUNET_GC_Configuration *
GNUNET_GC_create ()
{
  GNUNET_GC_Configuration *ret;

  ret = GNUNET_malloc (sizeof (GNUNET_GC_Configuration));
  memset (ret, 0, sizeof (GNUNET_GC_Configuration));
  ret->lock = GNUNET_mutex_create (GNUNET_YES);
  return ret;
}

/**
 * Get a configuration value that should be in a set of
 * "GNUNET_YES" or "GNUNET_NO".
 *
 * @param def default value (use indicated by return value;
 *        will NOT be aliased, maybe NULL)
 * @return GNUNET_YES, GNUNET_NO or GNUNET_SYSERR
 */
int
GNUNET_GC_get_configuration_value_yesno (struct GNUNET_GC_Configuration *cfg,
                                         const char *section,
                                         const char *option, int def)
{
  static const char *yesno[] = { "YES", "NO", NULL };
  const char *val;
  int ret;

  ret = GNUNET_GC_get_configuration_value_choice (cfg,
                                                  section,
                                                  option,
                                                  yesno,
                                                  def ==
                                                  GNUNET_YES ? "YES" : "NO",
                                                  &val);
  if (ret == -1)
    return GNUNET_SYSERR;
  if (val == yesno[0])
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Iterate over the set of filenames stored in a configuration value.
 *
 * @return number of filenames iterated over, -1 on error
 */
int
GNUNET_GC_iterate_configuration_value_filenames (struct
                                                 GNUNET_GC_Configuration *cfg,
                                                 const char *section,
                                                 const char *option,
                                                 GNUNET_FileNameCallback cb,
                                                 void *cls)
{
  char *list;
  char *pos;
  char *end;
  char old;
  int ret;

  if (GNUNET_NO == GNUNET_GC_have_configuration_value (cfg, section, option))
    return 0;
  GNUNET_GC_get_configuration_value_string (cfg,
                                            section, option, NULL, &list);
  ret = 0;
  pos = list;
  while (1)
    {
      while (pos[0] == ' ')
        pos++;
      if (strlen (pos) == 0)
        break;
      end = pos + 1;
      while ((end[0] != ' ') && (end[0] != '\0'))
        {
          if (end[0] == '\\')
            {
              switch (end[1])
                {
                case '\\':
                case ' ':
                  memmove (end, &end[1], strlen (&end[1]) + 1);
                case '\0':
                  /* illegal, but just keep it */
                  break;
                default:
                  /* illegal, but just ignore that there was a '/' */
                  break;
                }
            }
          end++;
        }
      old = end[0];
      end[0] = '\0';
      if (strlen (pos) > 0)
        {
          ret++;
          if ((cb != NULL) && (GNUNET_OK != cb (cls, pos)))
            {
              ret = GNUNET_SYSERR;
              break;
            }
        }
      if (old == '\0')
        break;
      pos = end + 1;
    }
  GNUNET_free (list);
  return ret;
}

static char *
escape_name (const char *value)
{
  char *escaped;
  const char *rpos;
  char *wpos;

  escaped = GNUNET_malloc (strlen (value) * 2 + 1);
  memset (escaped, 0, strlen (value) * 2 + 1);
  rpos = value;
  wpos = escaped;
  while (rpos[0] != '\0')
    {
      switch (rpos[0])
        {
        case '\\':
        case ' ':
          wpos[0] = '\\';
          wpos[1] = rpos[0];
          wpos += 2;
          break;
        default:
          wpos[0] = rpos[0];
          wpos++;
        }
      rpos++;
    }
  return escaped;
}

static int
test_match (void *cls, const char *fn)
{
  const char *of = cls;
  return (0 == strcmp (of, fn)) ? GNUNET_SYSERR : GNUNET_OK;
}

/**
 * Append a filename to a configuration value that
 * represents a list of filenames
 *
 * @param value filename to append
 * @return GNUNET_OK on success,
 *         GNUNET_NO if the filename already in the list
 *         GNUNET_SYSERR on error
 */
int
GNUNET_GC_append_configuration_value_filename (struct GNUNET_GC_Configuration
                                               *cfg,
                                               struct GNUNET_GE_Context *ectx,
                                               const char *section,
                                               const char *option,
                                               const char *value)
{
  char *escaped;
  char *old;
  char *nw;
  int ret;

  if (GNUNET_SYSERR
      == GNUNET_GC_iterate_configuration_value_filenames (cfg,
                                                          section,
                                                          option,
                                                          &test_match,
                                                          (void *) value))
    return GNUNET_NO;           /* already exists */
  if (GNUNET_NO == GNUNET_GC_have_configuration_value (cfg, section, option))
    old = GNUNET_strdup ("");
  else
    GNUNET_GC_get_configuration_value_string (cfg,
                                              section, option, NULL, &old);
  escaped = escape_name (value);
  nw = GNUNET_malloc (strlen (old) + strlen (escaped) + 2);
  strcpy (nw, old);
  strcat (nw, " ");
  strcat (nw, escaped);
  ret = GNUNET_GC_set_configuration_value_string (cfg,
                                                  ectx, section, option, nw);
  GNUNET_free (old);
  GNUNET_free (nw);
  GNUNET_free (escaped);
  return (ret == 0) ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Remove a filename from a configuration value that
 * represents a list of filenames
 *
 * @param value filename to remove
 * @return GNUNET_OK on success,
 *         GNUNET_NO if the filename is not in the list,
 *         GNUNET_SYSERR on error
 */
int
GNUNET_GC_remove_configuration_value_filename (struct GNUNET_GC_Configuration
                                               *cfg,
                                               struct GNUNET_GE_Context *ectx,
                                               const char *section,
                                               const char *option,
                                               const char *value)
{
  char *list;
  char *pos;
  char *end;
  char *match;
  char old;
  int ret;

  if (GNUNET_NO == GNUNET_GC_have_configuration_value (cfg, section, option))
    return GNUNET_NO;
  GNUNET_GC_get_configuration_value_string (cfg,
                                            section, option, NULL, &list);
  match = escape_name (value);
  ret = 0;
  pos = list;
  while (1)
    {
      while (pos[0] == ' ')
        pos++;
      if (strlen (pos) == 0)
        break;
      end = pos + 1;
      while ((end[0] != ' ') && (end[0] != '\0'))
        {
          if (end[0] == '\\')
            {
              switch (end[1])
                {
                case '\\':
                case ' ':
                  end++;
                  break;
                case '\0':
                  /* illegal, but just keep it */
                  break;
                default:
                  /* illegal, but just ignore that there was a '/' */
                  break;
                }
            }
          end++;
        }
      old = end[0];
      end[0] = '\0';
      if (strlen (pos) > 0)
        {
          if (0 == strcmp (pos, match))
            {
              memmove (pos, &end[1], strlen (&end[1]) + 1);

              if (pos != list)
                pos[-1] = ' ';  /* previously changed to "\0" */
              ret = GNUNET_GC_set_configuration_value_string (cfg,
                                                              ectx,
                                                              section,
                                                              option, list);
              GNUNET_free (list);
              GNUNET_free (match);
              return (ret == 0) ? GNUNET_OK : GNUNET_SYSERR;
            }
        }
      if (old == '\0')
        break;
      pos = end + 1;
    }
  GNUNET_free (list);
  GNUNET_free (match);
  return GNUNET_NO;
}

/* end of config.c */

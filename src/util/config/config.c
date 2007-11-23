/*
     This file is part of GNUnet.
     (C) 2006, 2007 Christian Grothoff (and other contributing authors)

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

#include "gnunet_util.h"
#include "platform.h"

/**
 * @brief configuration entry
 */
typedef struct GC_Entry
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
} GC_Entry;

/**
 * @brief configuration section
 */
typedef struct GC_Section
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
  GC_Entry *entries;
} GC_Section;

/**
 * @brief GC_ChangeListener and context
 */
typedef struct GC_Listener
{

  /**
   * Callback.
   */
  GC_ChangeListener listener;

  /**
   * Context for callback.
   */
  void *ctx;
} GC_Listener;

/**
 * @brief configuration data
 */
typedef struct GC_Configuration
{

  /**
   * Lock to access the data.
   */
  struct GNUNET_Mutex *lock;

  /**
   * Context for logging errors, maybe NULL.
   */
  struct GE_Context *ectx;

  /**
   * Modification indication since last save
   * 0 if clean, 1 if dirty, -1 on error (i.e. last save failed)
   */
  int dirty;

  /**
   * How many sections do we have?
   */
  unsigned int ssize;

  /**
   * Array with "ssize" entries.
   */
  GC_Section *sections;

  /**
   * How many listeners do we have?
   */
  unsigned int lsize;

  /**
   * Array with "lsize" entries.
   */
  GC_Listener *listeners;

} GC_Configuration;

void
GC_free (struct GC_Configuration *cfg)
{
  GC_Section *sec;
  GC_Entry *e;
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
          GE_ASSERT (cfg->ectx, e->dirty_val == NULL);
        }
      GNUNET_array_grow (sec->entries, sec->size, 0);
      GNUNET_free (sec->name);
    }
  GNUNET_array_grow (cfg->sections, cfg->ssize, 0);
  GE_ASSERT (cfg->ectx, cfg->listeners == 0);
  GNUNET_mutex_destroy (cfg->lock);
  GNUNET_free (cfg);
  GNUNET_free (cfg);
}

void
GC_set_error_context (struct GC_Configuration *cfg, struct GE_Context *ectx)
{
  cfg->ectx = ectx;
}

int
GC_parse_configuration (struct GC_Configuration *cfg, const char *filename)
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
      GE_LOG_STRERROR_FILE (cfg->ectx,
                            GE_ERROR | GE_USER | GE_IMMEDIATE | GE_BULK |
                            GE_REQUEST, "fopen", fn);
      GNUNET_mutex_unlock (cfg->lock);
      GNUNET_free (fn);
      return -1;
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
          if (0 != GC_parse_configuration (cfg, expanded))
            ret = -1;           /* failed to parse included config */
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
          if ((GNUNET_NO == GC_have_configuration_value (cfg,
                                                         section,
                                                         tag)) &&
              (0 != GC_set_configuration_value_string (cfg,
                                                       cfg->ectx,
                                                       section,
                                                       tag, &value[i])))
            ret = -1;           /* could not set value */
        }
      else if (1 == sscanf (line, " %63[^= ] =[^\n]", tag))
        {
          /* tag = */
          /* first check if we have this value already;
             this could happen if the value was changed
             using a command-line option; only set it
             if we do not have a value already... */
          if ((GNUNET_NO == GC_have_configuration_value (cfg,
                                                         section,
                                                         tag)) &&
              (0 != GC_set_configuration_value_string (cfg,
                                                       cfg->ectx,
                                                       section, tag, "")))
            ret = -1;           /* could not set value */
        }
      else
        {
          /* parse error */
          GE_LOG (cfg->ectx,
                  GE_ERROR | GE_USER | GE_IMMEDIATE | GE_BULK,
                  _("Syntax error in configuration file `%s' at line %d.\n"),
                  filename, nr);
          ret = -1;
          break;
        }
    }
  if (0 != fclose (fp))
    {
      GE_LOG_STRERROR_FILE (cfg->ectx,
                            GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE |
                            GE_BULK | GE_REQUEST, "fclose", filename);
      ret = -1;
    }
  /* restore dirty flag - anything we set in the meantime
     came from disk */
  cfg->dirty = dirty;
  GNUNET_mutex_unlock (cfg->lock);
  GNUNET_free (section);
  return ret;
}

int
GC_test_dirty (struct GC_Configuration *cfg)
{
  return cfg->dirty;
}

int
GC_write_configuration (struct GC_Configuration *data, const char *filename)
{
  GC_Section *sec;
  GC_Entry *e;
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
      GE_LOG_STRERROR_FILE (data->ectx,
                            GE_ERROR | GE_USER | GE_IMMEDIATE, "fopen", fn);
      GNUNET_free (fn);
      return -1;
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
          GE_ASSERT (data->ectx, e->dirty_val == NULL);
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
    GE_LOG_STRERROR_FILE (data->ectx,
                          GE_ERROR | GE_USER | GE_IMMEDIATE | GE_BULK |
                          GE_REQUEST, "fprintf", filename);
  if (0 != fclose (fp))
    {
      GE_LOG_STRERROR_FILE (data->ectx,
                            GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE |
                            GE_BULK | GE_REQUEST, "fclose", filename);
      error = 1;
    }
  if (error == 0)
    {
      ret = 0;
      data->dirty = 0;          /* last write succeeded */
    }
  else
    {
      ret = -1;
      data->dirty = -1;         /* last write failed */
    }
  GNUNET_mutex_unlock (data->lock);
  return ret;
}

/**
 * Call only with lock held!
 */
static GC_Section *
findSection (GC_Configuration * data, const char *section)
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
static GC_Entry *
findEntry (GC_Configuration * data, const char *section, const char *key)
{
  int i;
  GC_Section *sec;

  sec = findSection (data, section);
  if (sec == NULL)
    return NULL;
  for (i = sec->size - 1; i >= 0; i--)
    if (0 == strcmp (key, sec->entries[i].key))
      return &sec->entries[i];
  return NULL;
}

int
GC_set_configuration_value_string (struct GC_Configuration *data,
                                   struct GE_Context *ectx,
                                   const char *section,
                                   const char *option, const char *value)
{
  GC_Section *sec;
  GC_Section nsec;
  GC_Entry *e;
  GC_Entry ne;
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
          GE_BREAK (ectx, 0);
          ret = -1;
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
                GE_ASSERT (ectx, 0);    /* refused the refusal!? */
              e = findEntry (data, section, option);    /* side-effects of callback are possible! */
              i++;
            }
          ret = -1;             /* error -- update refused */
        }
      else
        {
          /* all confirmed, commit! */
          if ((e->val == NULL) || (0 != strcmp (e->val, e->dirty_val)))
            data->dirty = 1;
          GNUNET_free_non_null (e->val);
          e->val = e->dirty_val;
          e->dirty_val = NULL;
          ret = 0;
        }
    }
  if (ret == -1)
    GE_LOG (ectx,
            GE_USER | GE_BULK | GE_WARNING,
            _
            ("Setting option `%s' in section `%s' to value `%s' was refused.\n"),
            option, section, value);
  GNUNET_mutex_unlock (data->lock);
  return ret;
}

int
GC_set_configuration_value_number (struct GC_Configuration *cfg,
                                   struct GE_Context *ectx,
                                   const char *section,
                                   const char *option,
                                   unsigned long long number)
{
  char s[64];
  GNUNET_snprintf (s, 64, "%llu", number);
  return GC_set_configuration_value_string (cfg, ectx, section, option, s);
}

int
GC_get_configuration_value_number (struct GC_Configuration *cfg,
                                   const char *section,
                                   const char *option,
                                   unsigned long long min,
                                   unsigned long long max,
                                   unsigned long long def,
                                   unsigned long long *number)
{
  GC_Entry *e;
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
              ret = 0;
            }
          else
            {
              GE_LOG (cfg->ectx,
                      GE_ERROR | GE_USER | GE_BULK,
                      _("Configuration value '%llu' for '%s' "
                        "in section '%s' is out of legal bounds [%llu,%llu]\n"),
                      *number, option, section, min, max);
              ret = -1;         /* error */
            }
        }
      else
        {
          GE_LOG (cfg->ectx,
                  GE_ERROR | GE_USER | GE_BULK,
                  _("Configuration value '%s' for '%s'"
                    " in section '%s' should be a number\n"),
                  val, option, section, min, max);
          ret = -1;             /* error */
        }
    }
  else
    {
      *number = def;
      GC_set_configuration_value_number (cfg,
                                         cfg->ectx, section, option, def);
      ret = 1;                  /* default */
    }
  GNUNET_mutex_unlock (cfg->lock);
  return ret;
}

int
GC_get_configuration_value_string (struct GC_Configuration *cfg,
                                   const char *section,
                                   const char *option,
                                   const char *def, char **value)
{
  GC_Entry *e;
  const char *val;
  int ret;

  GNUNET_mutex_lock (cfg->lock);
  e = findEntry (cfg, section, option);
  if (e != NULL)
    {
      val = (e->dirty_val != NULL) ? e->dirty_val : e->val;
      *value = GNUNET_strdup (val);
      ret = 0;
    }
  else
    {
      if (def == NULL)
        {
          GNUNET_mutex_unlock (cfg->lock);
          GE_LOG (cfg->ectx,
                  GE_USER | GE_IMMEDIATE | GE_ERROR,
                  "Configuration value for option `%s' in section `%s' required.\n",
                  option, section);
          return -1;
        }
      *value = GNUNET_strdup (def);
      GC_set_configuration_value_string (cfg,
                                         cfg->ectx, section, option, def);
      ret = 1;                  /* default */
    }
  GNUNET_mutex_unlock (cfg->lock);
  return ret;
}

int
GC_get_configuration_value_choice (struct GC_Configuration *cfg,
                                   const char *section,
                                   const char *option,
                                   const char **choices,
                                   const char *def, const char **value)
{
  GC_Entry *e;
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
          GE_LOG (cfg->ectx,
                  GE_ERROR | GE_USER | GE_BULK,
                  _("Configuration value '%s' for '%s'"
                    " in section '%s' is not in set of legal choices\n"),
                  val, option, section);
          ret = -1;             /* error */
        }
      else
        {
          *value = choices[i];
          ret = 0;
        }
    }
  else
    {
      *value = def;
      if (def == NULL)
        ret = -1;
      else
        ret = 1;                /* default */
    }
  GNUNET_mutex_unlock (cfg->lock);
  return ret;
}

/**
 * Test if we have a value for a particular option
 * @return GNUNET_YES if so, GNUNET_NO if not.
 */
int
GC_have_configuration_value (struct GC_Configuration *cfg,
                             const char *section, const char *option)
{
  GC_Entry *e;
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
GC_configuration_expand_dollar (struct GC_Configuration *cfg, char *orig)
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
  if (GNUNET_YES == GC_have_configuration_value (cfg, "PATHS", &orig[1]))
    {
      if (0 != GC_get_configuration_value_string (cfg,
                                                  "PATHS",
                                                  &orig[1], NULL, &prefix))
        {
          GE_BREAK (NULL, 0);
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
GC_get_configuration_value_filename (struct GC_Configuration *data,
                                     const char *section,
                                     const char *option,
                                     const char *def, char **value)
{
  int ret;
  char *tmp;

  tmp = NULL;
  ret = GC_get_configuration_value_string (data, section, option, def, &tmp);
  if (tmp != NULL)
    {
      tmp = GC_configuration_expand_dollar (data, tmp);
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
GC_set_configuration_value_choice (struct GC_Configuration *cfg,
                                   struct GE_Context *ectx,
                                   const char *section,
                                   const char *option, const char *choice)
{
  return GC_set_configuration_value_string (cfg, ectx, section, option,
                                            choice);
}

int
GC_attach_change_listener (struct GC_Configuration *cfg,
                           GC_ChangeListener callback, void *ctx)
{
  GC_Listener l;
  int i;
  int j;

  GNUNET_mutex_lock (cfg->lock);
  for (i = 0; i < cfg->ssize; i++)
    {
      GC_Section *s = &cfg->sections[i];
      for (j = 0; j < s->size; j++)
        {
          GC_Entry *e = &s->entries[j];
          if (0 != callback (ctx, cfg, cfg->ectx, s->name, e->key))
            {
              GNUNET_mutex_unlock (cfg->lock);
              return -1;
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
GC_detach_change_listener (struct GC_Configuration *cfg,
                           GC_ChangeListener callback, void *ctx)
{
  int i;
  GC_Listener *l;

  GNUNET_mutex_lock (cfg->lock);
  for (i = cfg->lsize - 1; i >= 0; i--)
    {
      l = &cfg->listeners[i];
      if ((l->listener == callback) && (l->ctx == ctx))
        {
          cfg->listeners[i] = cfg->listeners[cfg->lsize - 1];
          GNUNET_array_grow (cfg->listeners, cfg->lsize, cfg->lsize - 1);
          GNUNET_mutex_unlock (cfg->lock);
          return 0;
        }
    }
  GNUNET_mutex_unlock (cfg->lock);
  return -1;
}

/**
 * Create a GC_Configuration.
 */
GC_Configuration *
GC_create ()
{
  GC_Configuration *ret;

  ret = GNUNET_malloc (sizeof (GC_Configuration));
  memset (ret, 0, sizeof (GC_Configuration));
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
GC_get_configuration_value_yesno (struct GC_Configuration *cfg,
                                  const char *section,
                                  const char *option, int def)
{
  static const char *yesno[] = { "YES", "NO", NULL };
  const char *val;
  int ret;

  ret = GC_get_configuration_value_choice (cfg,
                                           section,
                                           option,
                                           yesno,
                                           def == GNUNET_YES ? "YES" : "NO",
                                           &val);
  if (ret == -1)
    return GNUNET_SYSERR;
  if (val == yesno[0])
    return GNUNET_YES;
  return GNUNET_NO;
}

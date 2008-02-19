/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 * Released under the terms of the GNU GPL v2.0.
 */

/**
 * @file text/conf.c
 * @brief GNUnet Setup
 * @author Roman Zippel
 * @author Nils Durner
 * @author Christian Grothoff
 *
 * TODO:
 * - support editing of string inputs...
 */

#include "gnunet_setup_lib.h"
#include "conf.h"
#include "platform.h"
#include <termios.h>

static char
rd ()
{
  size_t ret;
  char c;

  ret = fread (&c, 1, 1, stdin);
  if (ret == 1)
    return c;
  return 'q';                   /* quit */
}

/**
 * printf with indentation
 */
static void
iprintf (int indent, const char *format, ...)
{
  int i;
  va_list va;

  for (i = 0; i < indent; i++)
    printf (" ");
  va_start (va, format);
  vfprintf (stdout, format, va);
  va_end (va);
  fflush (stdout);
}

static char *
getValueAsString (GNUNET_GNS_TreeNodeKindAndType type, GNUNET_GNS_Value * val)
{
  char buf[92];

  switch (type & GNUNET_GNS_TYPE_MASK)
    {
    case GNUNET_GNS_TYPE_BOOLEAN:
      if (val->Boolean.val)
        return GNUNET_strdup (_("yes"));
      return GNUNET_strdup (_("no"));
    case GNUNET_GNS_TYPE_STRING:
    case GNUNET_GNS_TYPE_SINGLE_CHOICE:
    case GNUNET_GNS_TYPE_MULTIPLE_CHOICE:
      return GNUNET_strdup (val->String.val);
    case GNUNET_GNS_TYPE_DOUBLE:
      GNUNET_snprintf (buf, 92, "%f", val->Double.val);
      return GNUNET_strdup (buf);
    case GNUNET_GNS_TYPE_UINT64:
      GNUNET_snprintf (buf, 92, "%llu", val->UInt64.val);
      return GNUNET_strdup (buf);
    }
  return GNUNET_strdup ("Internal error.");
}

static void
printChoice (int indent, GNUNET_GNS_TreeNodeKindAndType type,
             GNUNET_GNS_Value * val)
{
  int i;
  char defLet;

  switch (type & GNUNET_GNS_TYPE_MASK)
    {
    case GNUNET_GNS_TYPE_BOOLEAN:
      iprintf (indent,
               _("\tEnter yes (%s), no (%s) or help (%s): "),
               val->Boolean.def ? "Y" : "y",
               val->Boolean.def ? "n" : "N", "d", "?");
      break;
    case GNUNET_GNS_TYPE_STRING:
    case GNUNET_GNS_TYPE_MULTIPLE_CHOICE:
      i = 0;
      defLet = '\0';
      if (val->String.legalRange[0] != NULL)
        iprintf (indent, _("\tPossible choices:\n"));
      while (val->String.legalRange[i] != NULL)
        {
          iprintf (indent, "\t %s\n", val->String.legalRange[i]);
          i++;
        }
      iprintf (indent,
               _
               ("\tUse single space prefix to avoid conflicts with hotkeys!\n"));
      iprintf (indent,
               _("\tEnter string (type '%s' for default value `%s'): "), "d",
               val->String.def);
      break;
    case GNUNET_GNS_TYPE_SINGLE_CHOICE:
      i = 0;
      defLet = '\0';
      while (val->String.legalRange[i] != NULL)
        {
          iprintf (indent,
                   "\t (%c) %s\n",
                   (i < 10) ? '0' + i : 'a' + i - 10,
                   val->String.legalRange[i]);
          if (0 == strcmp (val->String.legalRange[i], val->String.def))
            defLet = (i < 10) ? '0' + i : 'a' + i - 10;
          i++;
        }
      GNUNET_GE_ASSERT (NULL, defLet != '\0');
      iprintf (indent, "\n\t (?) Help\n");
      iprintf (indent, _("\t Enter choice (default is %c): "), defLet);
      break;
    case GNUNET_GNS_TYPE_DOUBLE:
      iprintf (indent,
               _("\tEnter floating point (type '%s' for default value %f): "),
               "d", val->Double.def);
      break;
    case GNUNET_GNS_TYPE_UINT64:
      iprintf (indent,
               _
               ("\tEnter unsigned integer in interval [%llu,%llu] (type '%s' for default value %llu): "),
               val->UInt64.min, val->UInt64.max, "d", val->UInt64.def);
      break;
    default:
      return;
    }
}

/**
 * @return GNUNET_OK on success, GNUNET_NO to display help, GNUNET_SYSERR to abort
 */
static int
readValue (GNUNET_GNS_TreeNodeKindAndType type, GNUNET_GNS_Value * val)
{
  int c;
  char buf[1024];
  int i;
  int j;
  unsigned long long l;

  switch (type & GNUNET_GNS_TYPE_MASK)
    {
    case GNUNET_GNS_TYPE_BOOLEAN:
      while (1)
        {
          c = rd ();
          switch (c)
            {
            case '\n':
              printf ("\n");
              return GNUNET_YES;        /* skip */
            case 'y':
            case 'Y':
              val->Boolean.val = 1;
              printf (_("Yes\n"));
              return GNUNET_YES;
            case 'n':
            case 'N':
              val->Boolean.val = 0;
              printf (_("No\n"));
              return GNUNET_YES;
            case '?':
              printf (_("Help\n"));
              return GNUNET_NO;
            case 'q':
              printf (_("Abort\n"));
              return GNUNET_SYSERR;
            default:
              break;
            }
        }
      break;
    case GNUNET_GNS_TYPE_STRING:
    case GNUNET_GNS_TYPE_MULTIPLE_CHOICE:
      i = 0;
      while (1)
        {
          buf[i] = rd ();
          if (buf[i] == 'q')
            {
              printf (_("Abort\n"));
              return GNUNET_SYSERR;
            }
#if 0
          if (buf[i] == '\b')
            {
              if (i > 0)
                {
                  printf ("\b");        /* this does not work */
                  i--;
                }
              continue;
            }
#endif
          if ((buf[i] == 'd') && (i == 0))
            {
              printf ("%s\n", val->String.def);
              GNUNET_free (val->String.val);
              val->String.val = GNUNET_strdup (val->String.def);
              return GNUNET_YES;
            }
          if ((buf[i] == '?') && (i == 0))
            {
              printf (_("Help\n"));
              return GNUNET_NO;
            }
          if ((buf[i] == '\n') && (i == 0))
            {
              printf ("%s\n", val->String.val);
              return GNUNET_YES;        /* keep */
            }
          if (buf[i] != '\n')
            {
              if (i < 1023)
                {
                  printf ("%c", buf[i]);
                  fflush (stdout);
                  i++;
                }
              continue;
            }
          break;
        }
      GNUNET_free (val->String.val);
      val->String.val = GNUNET_strdup (buf[0] == ' ' ? &buf[1] : buf);
      printf ("\n");
      return GNUNET_OK;
    case GNUNET_GNS_TYPE_SINGLE_CHOICE:
      while (1)
        {
          c = rd ();
          if (c == '?')
            {
              printf (_("Help\n"));
              return GNUNET_NO;
            }
          if (c == '\n')
            {
              printf ("%s\n", val->String.val);
              return GNUNET_YES;
            }
          if (c == 'q')
            {
              printf (_("Abort\n"));
              return GNUNET_SYSERR;
            }
          i = -1;
          if ((c >= '0') && (c <= '9'))
            i = c - '0';
          else if ((c >= 'a') && (c <= 'z'))
            i = c - 'a' + 10;
          else
            continue;           /* invalid entry */
          for (j = 0; j <= i; j++)
            if (val->String.legalRange[j] == NULL)
              {
                i = -1;
                break;
              }
          if (i == -1)
            continue;           /* invalid entry */
          GNUNET_free (val->String.val);
          val->String.val = GNUNET_strdup (val->String.legalRange[i]);
          printf ("%s\n", val->String.val);
          return GNUNET_OK;
        }
      /* unreachable */
    case GNUNET_GNS_TYPE_DOUBLE:
      i = 0;
      while (1)
        {
          buf[i] = rd ();
          if (buf[i] == 'q')
            {
              printf (_("Abort\n"));
              return GNUNET_SYSERR;
            }
#if 0
          if (buf[i] == '\b')
            {
              if (i > 0)
                {
                  printf ("\b");        /* this does not work */
                  i--;
                }
              continue;
            }
#endif
          if ((buf[i] == 'd') && (i == 0))
            {
              val->Double.val = val->Double.def;
              printf ("%f\n", val->Double.val);
              return GNUNET_YES;        /* default */
            }
          if (buf[i] == '?')
            {
              printf (_("Help\n"));
              return GNUNET_NO;
            }
          if (buf[i] != '\n')
            {
              if (i < 1023)
                {
                  printf ("%c", buf[i]);
                  fflush (stdout);
                  i++;
                }
              continue;
            }
          if (i == 0)
            {
              printf ("%f\n", val->Double.val);
              return GNUNET_YES;        /* keep */
            }
          buf[i + 1] = '\0';
          if (1 == sscanf (buf, "%lf", &val->Double.val))
            {
              printf ("\n");
              return GNUNET_OK;
            }
          i = 0;
          printf (_("\nInvalid entry, try again (use '?' for help): "));
          fflush (stdout);
        }
      break;
    case GNUNET_GNS_TYPE_UINT64:
      i = 0;
      while (1)
        {
          buf[i] = rd ();
          if (buf[i] == 'q')
            {
              printf (_("Abort\n"));
              return GNUNET_SYSERR;
            }
#if 0
          if (buf[i] == '\b')
            {
              if (i > 0)
                {
                  printf ("\b");        /* does not work */
                  i--;
                }
              continue;
            }
#endif
          if ((buf[i] == 'd') && (i == 0))
            {
              val->UInt64.val = val->UInt64.def;
              printf ("%llu\n", val->UInt64.val);
              return GNUNET_YES;        /* default */
            }
          if (buf[i] == '?')
            {
              printf (_("Help\n"));
              return GNUNET_NO;
            }
          if (buf[i] != '\n')
            {
              if (i < 1023)
                {
                  printf ("%c", buf[i]);
                  fflush (stdout);
                  i++;
                }
              continue;
            }
          if (i == 0)
            {
              printf ("%llu\n", val->UInt64.val);
              return GNUNET_YES;        /* keep */
            }
          buf[i + 1] = '\0';
          if ((1 == sscanf (buf,
                            "%llu",
                            &l)) &&
              (l >= val->UInt64.min) && (l <= val->UInt64.max))
            {
              val->UInt64.val = l;
              printf ("\n");
              return GNUNET_OK;
            }
          i = 0;
          printf (_("\nInvalid entry, try again (use '?' for help): "));
          fflush (stdout);
        }
      break;
    default:
      fprintf (stderr,
               _("Unknown kind %x (internal error).  Skipping option.\n"),
               type & GNUNET_GNS_TYPE_MASK);
      return GNUNET_OK;
    }
  return GNUNET_OK;
}

static int
conf (int indent,
      struct GNUNET_GC_Configuration *cfg,
      struct GNUNET_GE_Context *ectx, struct GNUNET_GNS_TreeNode *tree)
{
  char choice;
  char *value;
  char *ovalue;
  int i;

  if (!tree->visible)
    return GNUNET_OK;
  switch (tree->type & GNUNET_GNS_KIND_MASK)
    {
    case GNUNET_GNS_KIND_LEAF:
      ovalue = getValueAsString (tree->type, &tree->value);
      while (1)
        {
          iprintf (indent,
                   "[%s] %s = \"%s\"\n", tree->section, tree->option, ovalue);
          iprintf (indent, "%s\n", gettext (tree->description));
          printChoice (indent, tree->type, &tree->value);
          i = readValue (tree->type, &tree->value);
          if (i == GNUNET_SYSERR)
            {
              GNUNET_free (ovalue);
              return GNUNET_SYSERR;
            }
          if (i == GNUNET_OK)
            break;
          printf ("\n\n");
          iprintf (0, "%s\n", gettext (tree->help));
          printf ("\n");
        }
      value = getValueAsString (tree->type, &tree->value);
      if ((0 != strcmp (value, ovalue)) &&
          (0 != GNUNET_GC_set_configuration_value_string (cfg,
                                                          ectx,
                                                          tree->section,
                                                          tree->option,
                                                          value)))
        {
          GNUNET_free (value);
          GNUNET_free (ovalue);
          return conf (indent, cfg, ectx, tree);        /* try again */
        }
      GNUNET_free (value);
      GNUNET_free (ovalue);
      return GNUNET_OK;
    case GNUNET_GNS_KIND_NODE:
      choice = '\0';
      while (choice == '\0')
        {
          iprintf (indent, "%s\n", gettext (tree->description));
          iprintf (indent, _(   /* do not translate y/n/? */
                              "\tDescend? (y/n/?) "));
          choice = rd ();
          switch (choice)
            {
            case 'N':
            case 'n':
              iprintf (indent, "%c\n", choice);
              return GNUNET_OK;
            case 'q':
              iprintf (indent, _("Aborted.\n"));
              return GNUNET_SYSERR;     /* escape */
            case '?':
              iprintf (indent, "%c\n", choice);
              iprintf (indent, "%s\n", gettext (tree->help));
              choice = '\0';
              break;
            case 'Y':
            case 'y':
              iprintf (indent, "%c\n", choice);
              break;
            default:
              iprintf (indent, "%c\n", choice);
              iprintf (indent, _("Invalid entry.\n"));
              choice = '\0';
              break;
            }
        }
      /* fall-through! */
    case GNUNET_GNS_KIND_ROOT:
      i = 0;
      while (tree->children[i] != NULL)
        {
          if (GNUNET_SYSERR ==
              conf (indent + 1, cfg, ectx, tree->children[i]))
            return GNUNET_SYSERR;
          i++;
        }
      return GNUNET_OK;
    default:
      fprintf (stderr,
               _("Unknown kind %x (internal error).  Aborting.\n"),
               tree->type & GNUNET_GNS_KIND_MASK);
      return GNUNET_SYSERR;
    }
  return GNUNET_SYSERR;
}

int
main_setup_text (int argc,
                 const char **argv,
                 struct GNUNET_PluginHandle *self,
                 struct GNUNET_GE_Context *ectx,
                 struct GNUNET_GC_Configuration *cfg,
                 struct GNUNET_GNS_Context *gns, const char *filename,
                 int is_daemon)
{
  struct GNUNET_GNS_TreeNode *root;
  struct termios oldT;
  struct termios newT;
  char c;
  int ret;

#if OSX || SOMEBSD
#  define TCGETS TIOCGETA
#  define TCSETS TIOCSETA
#endif
  ioctl (0, TCGETS, &oldT);
  newT = oldT;
  newT.c_lflag &= ~ECHO;
  newT.c_lflag &= ~ICANON;
  ioctl (0, TCSETS, &newT);

  printf (_("You can always press ENTER to keep the current value.\n"));
  printf (_("Use the '%s' key to abort.\n"), "q");
  root = GNUNET_GNS_get_tree_root (gns);
  c = 'r';
  while (c == 'r')
    {
      if (GNUNET_OK != conf (-1, cfg, ectx, root))
        {
          ioctl (0, TCSETS, &oldT);
          return 1;
        }
      if ((0 == GNUNET_GC_test_dirty (cfg)) && (0 == ACCESS (filename, R_OK)))
        {
          printf (_("Configuration unchanged, no need to save.\n"));
          ioctl (0, TCSETS, &oldT);
          return 0;
        }
      printf ("\n");
      printf (_
              ("Save configuration?  Answer 'y' for yes, 'n' for no, 'r' to repeat configuration. "));
      fflush (stdout);
      do
        {
          c = rd ();
        }
      while ((c != 'y') && (c != 'n') && (c != 'r'));
      printf ("%c\n", c);
      fflush (stdout);
    }
  if (c == 'y')
    {
      ret = GNUNET_GC_write_configuration (cfg, filename);
      if (ret == 1)
        {
          printf (_("Configuration was unchanged, no need to save.\n"));
        }
      else if (ret == -1)
        {                       /* error */
          ioctl (0, TCSETS, &oldT);
          return 1;
        }
      else
        {
          printf (_("Configuration file `%s' written.\n"), filename);
        }
    }
  ioctl (0, TCSETS, &oldT);
  return 0;
}


/**
 * Generate defaults, runs without user interaction.
 */
int
dump_setup_text (int argc,
                 const char **argv,
                 struct GNUNET_PluginHandle *self,
                 struct GNUNET_GE_Context *ectx,
                 struct GNUNET_GC_Configuration *cfg,
                 struct GNUNET_GNS_Context *gns, const char *filename,
                 int is_daemon)
{
  return GNUNET_GC_write_configuration (cfg, filename);
}

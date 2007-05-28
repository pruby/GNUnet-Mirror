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

static char rd() {
  size_t ret;
  char c;

  ret = fread(&c, 1, 1, stdin);
  if (ret == 1)
    return c;
  return 'q'; /* quit */
}

/**
 * printf with indentation
 */
static void iprintf(int indent,
		    const char * format,
		    ...) {
  int i;
  va_list va;

  for (i=0;i<indent;i++)
    printf(" ");
  va_start(va, format);
  vfprintf(stdout, format, va);
  va_end(va);
  fflush(stdout);
}

static char * getValueAsString(GNS_Type type,
			       GNS_Value * val) {
  char buf[92];

  switch (type & GNS_TypeMask) {
  case GNS_Boolean:
    if (val->Boolean.val)
      return STRDUP(_("yes"));
    return STRDUP(_("no"));
  case GNS_String:
  case GNS_SC:
  case GNS_MC:
    return STRDUP(val->String.val);
  case GNS_Double:
    SNPRINTF(buf, 92,
	     "%f",
	     val->Double.val);
    return STRDUP(buf);
  case GNS_UInt64:
    SNPRINTF(buf, 92,
	     "%llu",
	     val->UInt64.val);
    return STRDUP(buf);
  }
  return STRDUP("Internal error.");
}

static void printChoice(int indent,
			GNS_Type type,
			GNS_Value * val) {
  int i;
  char defLet;

  switch (type & GNS_TypeMask) {
  case GNS_Boolean:
    iprintf(indent,
	    _("\tEnter yes (%s), no (%s) or help (%s): "),
	    val->Boolean.def ? "Y" : "y",
	    val->Boolean.def ? "n" : "N",
	    "d",
	    "?");
    break;
  case GNS_String:
  case GNS_MC:
    i = 0;
    defLet = '\0';
    if (val->String.legalRange[0] != NULL)
      iprintf(indent,
	      _("\tPossible choices:\n"));
    while (val->String.legalRange[i] != NULL) {
      iprintf(indent,
	      "\t %s\n",
	      val->String.legalRange[i]);
      i++;
    }
    iprintf(indent,
	    _("\tUse single space prefix to avoid conflicts with hotkeys!\n"));
    iprintf(indent,
	    _("\tEnter string (type '%s' for default value `%s'): "),
	    "d",
	    val->String.def);
    break;
  case GNS_SC:
    i = 0;
    defLet = '\0';
    while (val->String.legalRange[i] != NULL) {
      iprintf(indent,
	      "\t (%c) %s\n",
	      (i < 10) ? '0' + i : 'a' + i - 10,
	      val->String.legalRange[i]);
      if (0 == strcmp(val->String.legalRange[i],
		      val->String.def))
	defLet = (i < 10) ? '0' + i : 'a' + i - 10;
      i++;
    }
    GE_ASSERT(NULL, defLet != '\0');
    iprintf(indent,
	    "\n\t (?) Help\n");
    iprintf(indent,
	    _("\t Enter choice (default is %c): "),
	    defLet);
    break;
  case GNS_Double:
    iprintf(indent,
	    _("\tEnter floating point (type '%s' for default value %f): "),
	    "d",
	    val->Double.def);
    break;
  case GNS_UInt64:
    iprintf(indent,
	    _("\tEnter unsigned integer in interval [%llu,%llu] (type '%s' for default value %llu): "),
	    val->UInt64.min,
	    val->UInt64.max,
	    "d",
	    val->UInt64.def);
    break;
  default:
    return;
  }
}

/**
 * @return OK on success, NO to display help, SYSERR to abort
 */
static int readValue(GNS_Type type,
		     GNS_Value * val) {
  int c;
  char buf[1024];
  int i;
  int j;
  unsigned long long l;

  switch (type & GNS_TypeMask) {
  case GNS_Boolean:
    while (1) {
      c = rd();
      switch (c) {
      case '\n':
	printf("\n");
	return YES; /* skip */
      case 'y':
      case 'Y':
	val->Boolean.val = 1;
	printf(_("Yes\n"));
	return YES;
      case 'n':
      case 'N':
	val->Boolean.val = 0;
	printf(_("No\n"));
	return YES;
      case '?':
	printf(_("Help\n"));
	return NO;
      case 'q':
	printf(_("Abort\n"));
	return SYSERR;
      default:
	break;
      }
    }
    break;
  case GNS_String:
  case GNS_MC:
    i = 0;
    while (1) {
      buf[i] = rd();
      if (buf[i] == 'q') {
	printf(_("Abort\n"));
	return SYSERR;
      }
#if 0
      if (buf[i] == '\b') {
	if (i > 0) {
	  printf("\b"); /* this does not work */
	  i--;
	}
	continue;
      }
#endif	
      if ( (buf[i] == 'd') && (i == 0) ) {
	printf("%s\n",
	       val->String.def);
	FREE(val->String.val);
	val->String.val = STRDUP(val->String.def);
	return YES;
      }
      if ( (buf[i] == '?') && (i == 0) ) {
	printf(_("Help\n"));
	return NO;
      }
      if ( (buf[i] == '\n') && (i == 0) ) {
	printf("%s\n",
	       val->String.val);
	return YES; /* keep */
      }
      if (buf[i] != '\n') {
	if (i < 1023) {
	  printf("%c", buf[i]);
	  fflush(stdout);
	  i++;
	}
	continue;
      }
      break;
    }
    FREE(val->String.val);
    val->String.val = STRDUP(buf[0] == ' ' ? &buf[1] : buf);
    printf("\n");
    return OK;
  case GNS_SC:
    while (1) {
      c = rd();
      if (c == '?') {
	printf(_("Help\n"));
	return NO;
      }
      if (c == '\n') {
	printf("%s\n",
	       val->String.val);
	return YES;
      }
      if (c == 'q') {
	printf(_("Abort\n"));
	return SYSERR;
      }
      i = -1;
      if ( (c >= '0') && (c <= '9') )
	i = c - '0';
      else if ( (c >= 'a') && (c <= 'z') )
	  i = c - 'a' + 10;
      else
	continue; /* invalid entry */
      for (j=0;j<=i;j++)
	if (val->String.legalRange[j] == NULL) {
	  i = -1;
	  break;
	}
      if (i == -1)
	continue; /* invalid entry */
      FREE(val->String.val);
      val->String.val = STRDUP(val->String.legalRange[i]);
      printf("%s\n",
	     val->String.val);
      return OK;
    }
    /* unreachable */
  case GNS_Double:
    i = 0;
    while (1) {
      buf[i] = rd();
      if (buf[i] == 'q') {
	printf(_("Abort\n"));
	return SYSERR;
      }
#if 0
      if (buf[i] == '\b') {
	if (i > 0) {
	  printf("\b"); /* this does not work */
	  i--;
	}
	continue;
      }
#endif
      if ( (buf[i] == 'd') && (i == 0) ) {
	val->Double.val = val->Double.def;
	printf("%f\n",
	       val->Double.val);
	return YES; /* default */
      }
      if (buf[i] == '?') {
	printf(_("Help\n"));
	return NO;
      }
      if (buf[i] != '\n') {
	if (i < 1023) {
	  printf("%c", buf[i]);
	  fflush(stdout);
	  i++;
	}
	continue;
      }
      if (i == 0) {
	printf("%f\n",
	       val->Double.val);
	return YES; /* keep */
      }
      buf[i+1] = '\0';
      if (1 == sscanf(buf,
		      "%lf",
		      &val->Double.val)) {
	printf("\n");
	return OK;
      }
      i = 0;
      printf(_("\nInvalid entry, try again (use '?' for help): "));
      fflush(stdout);
    }
    break;
  case GNS_UInt64:
    i = 0;
    while (1) {
      buf[i] = rd();
      if (buf[i] == 'q') {
	printf(_("Abort\n"));
	return SYSERR;
      }
#if 0
      if (buf[i] == '\b') {
	if (i > 0) {
	  printf("\b"); /* does not work */
	  i--;
	}
	continue;
      }
#endif
      if ( (buf[i] == 'd') && (i == 0) ) {
	val->UInt64.val = val->UInt64.def;
	printf("%llu\n",
	       val->UInt64.val);
	return YES; /* default */
      }
      if (buf[i] == '?') {
	printf(_("Help\n"));
	return NO;
      }
      if (buf[i] != '\n') {
	if (i < 1023) {
	  printf("%c", buf[i]);
	  fflush(stdout);
	  i++;
	}
	continue;
      }
      if (i == 0) {
	printf("%llu\n",
	       val->UInt64.val);
	return YES; /* keep */
      }
      buf[i+1] = '\0';
      if ( (1 == sscanf(buf,
			"%llu",
			&l)) &&
	   (l >= val->UInt64.min) &&
	   (l <= val->UInt64.max) ) {
	val->UInt64.val = l;
	printf("\n");
	return OK;
      }
      i = 0;
      printf(_("\nInvalid entry, try again (use '?' for help): "));
      fflush(stdout);
    }
    break;
  default:
    fprintf(stderr,
	    _("Unknown kind %x (internal error).  Skipping option.\n"),
	    type & GNS_TypeMask);
    return OK;
  }
  return OK;
}

static int conf(int indent,
		struct GC_Configuration * cfg,
		struct GE_Context * ectx,
		struct GNS_Tree * tree) {
  char choice;
  char * value;
  char * ovalue;
  int i;

  if (! tree->visible)
    return OK;
  switch (tree->type & GNS_KindMask) {
  case GNS_Leaf:
    ovalue = getValueAsString(tree->type,
			      &tree->value);
    while (1) {
      iprintf(indent,
	      "[%s] %s = \"%s\"\n",
	      tree->section,
	      tree->option,
	      ovalue);
      iprintf(indent,
	      "%s\n",
	      gettext(tree->description));
      printChoice(indent,
		  tree->type,
		  &tree->value);
      i = readValue(tree->type,
		    &tree->value);
      if (i == SYSERR) {
	FREE(ovalue);
	return SYSERR;
      }
      if (i == OK)
	break;
      printf("\n\n");
      iprintf(0,
	      "%s\n",
	      gettext(tree->help));
      printf("\n");
    }
    value = getValueAsString(tree->type,
			     &tree->value);
    if ( (0 != strcmp(value, ovalue)) &&
	 (0 != GC_set_configuration_value_string(cfg,
						 ectx,
						 tree->section,
						 tree->option,
						 value)) ) {
      FREE(value);
      FREE(ovalue);
      return conf(indent,
		  cfg,
		  ectx,
		  tree); /* try again */
    }
    FREE(value);
    FREE(ovalue);
    return OK;
  case GNS_Node:
    choice = '\0';
    while (choice == '\0') {
      iprintf(indent,
	      "%s\n",
	      gettext(tree->description));
      iprintf(indent,
	      _(/* do not translate y/n/? */
		"\tDescend? (y/n/?) "));
      choice = rd();
      switch(choice) {
      case 'N':
      case 'n':
	iprintf(indent,
		"%c\n",
		choice);
	return OK;
      case 'q':
	iprintf(indent,
		_("Aborted.\n"));
	return SYSERR; /* escape */
      case '?':
	iprintf(indent,
		"%c\n",
		choice);
	iprintf(indent,
		"%s\n",
		gettext(tree->help));
	choice = '\0';
	break;
      case 'Y':
      case 'y':
	iprintf(indent,
		"%c\n",
		choice);
	break;
      default:
	iprintf(indent,
		"%c\n",
		choice);
	iprintf(indent,
		_("Invalid entry.\n"));
	choice = '\0';
	break;
      }
    }
    /* fall-through! */
  case GNS_Root:
    i = 0;
    while (tree->children[i] != NULL) {
      if (SYSERR == conf(indent + 1,
			 cfg,
			 ectx,
			 tree->children[i]))
	return SYSERR;
      i++;
    }
    return OK;
  default:
    fprintf(stderr,
	    _("Unknown kind %x (internal error).  Aborting.\n"),
	    tree->type & GNS_KindMask);
    return SYSERR;
  }
  return SYSERR;
}

int main_setup_text(int argc,
		    const char **argv,
		    struct PluginHandle * self,
		    struct GE_Context * ectx,
		    struct GC_Configuration * cfg,
		    struct GNS_Context * gns,
		    const char * filename,
		    int is_daemon) {
  struct GNS_Tree * root;
  struct termios oldT;
  struct termios newT;
  char c;
  int ret;

#ifdef OSX
#  define TCGETS TIOCGETA
#  define TCSETS TIOCSETA
#endif
  ioctl(0, TCGETS, &oldT);
  newT = oldT;
  newT.c_lflag &= ~ECHO;
  newT.c_lflag &= ~ICANON;
  ioctl(0, TCSETS, &newT);

  printf(_("You can always press ENTER to keep the current value.\n"));
  printf(_("Use the '%s' key to abort.\n"),
	 "q");
  root = GNS_get_tree(gns);
  c = 'r';
  while (c == 'r') {
    if (OK != conf(-1,
		   cfg,
		   ectx,		
		   root)) {
      ioctl(0, TCSETS, &oldT);
      return 1;
    }
    if ( (0 == GC_test_dirty(cfg)) &&
	 (0 == ACCESS(filename, R_OK)) ) {
      printf(_("Configuration unchanged, no need to save.\n"));
      ioctl(0, TCSETS, &oldT);
      return 0;
    }
    printf("\n");
    printf(_("Save configuration?  Answer 'y' for yes, 'n' for no, 'r' to repeat configuration. "));
    fflush(stdout);
    do {
      c = rd();
    } while ( (c != 'y') && (c != 'n') && (c != 'r') );
    printf("%c\n", c);
    fflush(stdout);
  }
  if (c == 'y') {
    ret = GC_write_configuration(cfg,
				 filename);
    if (ret == 1) {
      printf(_("Configuration was unchanged, no need to save.\n"));
    } else if (ret == -1) { /* error */
      ioctl(0, TCSETS, &oldT);
      return 1;
    } else {
      printf(_("Configuration file `%s' written.\n"),
	     filename);
    }
  }
  ioctl(0, TCSETS, &oldT);
  return 0;
}


/**
 * Generate defaults, runs without user interaction.
 */
int dump_setup_text(int argc,
		    const char **argv,
		    struct PluginHandle * self,
		    struct GE_Context * ectx,
		    struct GC_Configuration * cfg,
		    struct GNS_Context * gns,
		    const char * filename,
		    int is_daemon) {
  return GC_write_configuration(cfg,
				filename);
}

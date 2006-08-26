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
 */

#include "gnunet_setup_lib.h"
#include "conf.h"
#include "platform.h"

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
}

static char * getValueAsString(GNS_Type type,
			       GNS_Value * val) {
  char buf[92];

  switch (type & (~ GNS_KindMask)) {
  case GNS_Boolean:
    if (val->Boolean.def)
      return STRDUP(_("yes"));
    return STRDUP(_("no"));
  case GNS_String:
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

  switch (type & (~ GNS_KindMask)) {
  case GNS_Boolean:
    iprintf(indent, 
	    _("\tEnter yes (%s) / no (%s) or help (%s): "),
	    val->Boolean.def ? "Y" : "y",
	    val->Boolean.def ? "n" : "N",
	    "?");
    break;
  case GNS_String:
    if (val->String.legalRange[0] == NULL) {
      iprintf(indent,
	      _("\tEnter string (default is `%s'): "),
	      val->String.def);
    } else {
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
    }
    break;
  case GNS_Double:
    iprintf(indent,
	    _("\tEnter floating point (default is %f): "),
	    val->Double.def);
    break;
  case GNS_UInt64:
    iprintf(indent,
	    _("\tEnter unsigned integer in interval [%llu,%llu] (default is %llu): "),
	    val->UInt64.min,
	    val->UInt64.max,
	    val->UInt64.def);
    break;
  default:
    GE_ASSERT(NULL, 0);
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
  
  switch (type & (~ GNS_KindMask)) {
  case GNS_Boolean:
    while (1) {
      c = fgetc(stdin);
      switch (c) {
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
      case '\n':
	val->Boolean.val = val->Boolean.def;
	if (val->Boolean.val)
	  printf(_("Yes\n"));
	else
	  printf(_("No\n"));
	return YES;
      case '?':
      case 'h':
      case 'H':
	printf(_("Help\n"));
	return NO;
      case '\x1b':
	printf(_("Abort\n"));
	return SYSERR;
      default:
	break;
      }
    }
    break;
  case GNS_String:
    if (val->String.legalRange[0] == NULL) {
      fgets(buf, 1024, stdin);
      FREE(val->String.val);
      val->String.val = STRDUP(buf);
      return OK;
    } else {
      while (1) {
	c = fgetc(stdin);
	if (c == '?') {
	  printf(_("Help\n"));
	  return NO;
	}
	if (c == '\x1b') {
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
    }
    break;
  case GNS_Double:
    while (1) {
      fgets(buf, 1024, stdin);
      if ( (buf[0] == '?') ||
	   (buf[0] == 'h') ||
	   (buf[0] == 'H') )
	return NO;
      if (buf[0] == '\n') {
	val->Double.val = val->Double.def;
	return YES;
      }
      if (buf[0] == '\x1b')
	return SYSERR;
      if (1 == sscanf(buf,
		      "%lf",
		      &val->Double.val))
	return OK;
      printf(_("\nInvalid entry, try again (use '?' for help): "));
    }
    break;
  case GNS_UInt64:
    while (1) {
      fgets(buf, 1024, stdin);
      if ( (buf[0] == '?') ||
	   (buf[0] == 'h') ||
	   (buf[0] == 'H') )
	return NO;
      if (buf[0] == '\n') {
	val->UInt64.val = val->UInt64.def;
	return YES;
      }
      if (buf[0] == '\x1b')
	return SYSERR;
      if ( (1 == sscanf(buf,
			"%llu",
			&l)) &&
	   (l >= val->UInt64.min) &&
	   (l <= val->UInt64.max) ) {
	val->UInt64.val = l;
	return OK;
      }
      printf(_("\nInvalid entry, try again (use '?' for help): "));
    }
    break;
  default:
    GE_ASSERT(NULL, 0);
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
	      tree->description);
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
	      tree->help);
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
      choice = fgetc(stdin);
      switch(choice) {
      case 'N':
      case 'n':
	iprintf(indent,
		"%c\n", choice);
	return OK;
      case '\x1b':
	iprintf(indent,
		_("Aborted.\n"));
	return SYSERR; /* escape */
      case '?':
      case 'h':
      case 'H':
	iprintf(indent,
		"%c\n", choice);
	iprintf(indent,
		gettext(tree->help));
	choice = '\0';
	break;
      case 'Y':
      case 'y':
	iprintf(indent,
		"%c\n", choice);
	break;
      default:
	iprintf(indent,
		"%c\n", choice);
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
  default:
    GE_ASSERT(NULL, 0);
    return SYSERR;
  }
}

int conf_main(int argc, 
	      const char **argv, 
	      struct PluginHandle * self,
	      struct GE_Context * ectx,
	      struct GC_Configuration * cfg,
	      struct GNS_Context * gns,
	      const char * filename,
	      int is_daemon) {
  struct GNS_Tree * root;

  root = GNS_get_tree(gns);
  if (OK != conf(-1,
		 cfg,
		 ectx,		 
		 root)) 
    return 1;
  if (-1 == GC_write_configuration(cfg,
				   filename)) 
    return 1;
  printf(_("Configuration file `%s' created.\n"),
	 filename);
  return 0;
}

/*
     This file is part of GNUnet
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
 * @file src/util/getopt/printhelp.c
 * @brief Common option processing methods for GNUnet clients.
 * @author Christian Grothoff
 */

#include "gnunet_util_string.h"
#include "gnunet_util_getopt.h"
#include "platform.h"

#define BORDER 29

int gnunet_getopt_format_help(CommandLineProcessorContext * ctx,
			      void * scls,
			      const char * option,
			      const char * value) {
  const char * about = scls;
  int slen;
  int i;
  int j;
  int ml;
  int p;
  char * scp;
  const char * trans;
  const struct CommandLineOption * opt;
	
  printf("%s\n%s\n",
	 ctx->binaryOptions,
	 gettext(about));
  printf(_("Arguments mandatory for long options are also mandatory for short options.\n"));
  slen = 0;
  i = 0;
  opt = ctx->allOptions;
  while (opt[i].description != NULL) {
    if (opt[i].shortName == '\0')
      printf("      ");
    else
      printf("  -%c, ",
	     opt[i].shortName);
    printf("--%s",
	   opt[i].name);
    slen = 8 + strlen(opt[i].name);
    if (opt[i].argumentHelp != NULL) {
      printf("=%s",
	     opt[i].argumentHelp);
      slen += 1+strlen(opt[i].argumentHelp);
    }
    if (slen > BORDER) {
      printf("\n%*s", BORDER, "");
      slen = BORDER;
    }
    if (slen < BORDER) {
      printf("%*s", BORDER-slen, "");
      slen = BORDER;
    }
    trans = gettext(opt[i].description);
    ml = strlen(trans);
    p = 0;
  OUTER:
    while (ml - p > 78 - slen) {
      for (j=p+78-slen;j>p;j--) {
	if (isspace(trans[j])) {
	  scp = MALLOC(j-p+1);
	  memcpy(scp,
		 &trans[p],
		 j-p);
	  scp[j-p] = '\0';
	  printf("%s\n%*s",
		 scp,
		 BORDER+2,
		 "");
	  FREE(scp);
	  p = j+1;
	  slen = BORDER+2;
	  goto OUTER;
	}
      }
      /* could not find space to break line */
      scp = MALLOC(78 - slen + 1);
      memcpy(scp,
	     &trans[p],
	     78 - slen);
      scp[78 - slen] = '\0';
      printf("%s\n%*s",
	     scp,
	     BORDER+2,
	     "");	
      FREE(scp);
      slen = BORDER+2;
      p = p + 78 - slen;
    }
    /* print rest */
    if (p < ml)
      printf("%s\n",
	     &trans[p]);
    if (strlen(trans) == 0)
      printf("\n");
    i++;
  }
  return SYSERR;
}

/* end of printhelp.c */

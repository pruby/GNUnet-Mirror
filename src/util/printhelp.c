/*
     This file is part of GNUnet

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
 * @file printhelp.c
 * @brief Common option processing methods for GNUnet clients.
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

#define BORDER 29


void formatHelp(const char * general,
		const char * description,
		const Help * opt) {
  int slen;
  int i;
  int j;
  int ml;
  int p;
  char * scp;
  const char * trans;
	
  printf(_("Usage: %s\n%s\n\n"),
	 gettext(general),
	 gettext(description));
  printf(_("Arguments mandatory for long options are also mandatory for short options.\n"));
  slen = 0;
  i = 0;
  while (opt[i].description != NULL) {
    if (opt[i].shortArg == 0)
      printf("      ");
    else
      printf("  -%c, ",
	     opt[i].shortArg);
    printf("--%s",
	   opt[i].longArg);
    slen = 8 + strlen(opt[i].longArg);
    if (opt[i].mandatoryArg != NULL) {
      printf("=%s",
	     opt[i].mandatoryArg);
      slen += 1+strlen(opt[i].mandatoryArg);
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
	  scp = malloc(j-p+1);
	  memcpy(scp,
		 &trans[p],
		 j-p);
	  scp[j-p] = '\0';
	  printf("%s\n%*s",
		 scp,
		 BORDER+2,
		 "");
	  free(scp);
	  p = j+1;
	  slen = BORDER+2;
	  goto OUTER;
	}
      }
      /* could not find space to break line */
      scp = malloc(78 - slen + 1);
      memcpy(scp,
	     &trans[p],
	     78 - slen);
      scp[78 - slen] = '\0';
      printf("%s\n%*s",
	     scp,
	     BORDER+2,
	     "");	
      free(scp);
      slen = BORDER+2;
      p = p + 78 - slen;
    }
    /* print rest */
    if (p < ml)
      printf("%s\n",
	     &trans[p]);
    i++;
  }
}

/**
 * Parse the default set of options and set
 * options in the configuration accordingly.
 * This does not include --help or --version.
 * @return YES if the option was a default option
 *  that was successfully processed
 */
int parseDefaultOptions(char c,
			char * optarg) {
  switch(c) {
  case 'c':
    FREENONNULL(setConfigurationString("FILES",
				       "gnunet.conf",
				       optarg));
    break;
  case 'd':
    FREENONNULL(setConfigurationString("GNUNETD",
				       "LOGFILE",
				       NULL));
    break;
  case 'H':
    FREENONNULL(setConfigurationString("NETWORK",
				       "HOST",
				       optarg));
    break;
  case 'L':
      FREENONNULL(setConfigurationString("GNUNET",
					 "LOGLEVEL",
					 optarg));
      break;
  default:
    return NO;
  }
  return YES;
}

/* end of printhelp.c */

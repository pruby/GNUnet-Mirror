/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file setup/text/conf.h
 * @brief GNUnet text mode Setup
 * @author Nils Durner
 */

#ifndef CONF_H
#define CONF_H

#include "gnunet_util.h"
#include "gnunet_setup_lib.h"

int main_setup_text(int argc,
		    const char ** argv,
		    struct PluginHandle * self,
		    struct GE_Context * ectx,
		    struct GC_Configuration * cfg,
		    struct GNS_Context * gns,
		    const char * filename,
		    int is_daemon);

#endif

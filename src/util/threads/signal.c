/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/threads/signal.c
 * @brief code for installing and uninstalling signal handlers
 * @author Christian Grothoff
 */

#include "gnunet_util_threads.h"
#include "gnunet_util_string.h"
#include "platform.h"

#ifndef MINGW
typedef struct GNUNET_SignalHandlerContext
{
  int sig;

  GNUNET_SignalHandler method;

  struct sigaction oldsig;
} SignalHandlerContext;

struct GNUNET_SignalHandlerContext *
GNUNET_signal_handler_install (int signal, GNUNET_SignalHandler handler)
{
  struct GNUNET_SignalHandlerContext *ret;
  struct sigaction sig;

  ret = GNUNET_malloc (sizeof (struct GNUNET_SignalHandlerContext));
  ret->sig = signal;
  ret->method = handler;

  sig.sa_handler = (void *) handler;
  sigemptyset (&sig.sa_mask);
#ifdef SA_INTERRUPT
  sig.sa_flags = SA_INTERRUPT;  /* SunOS */
#else
  sig.sa_flags = SA_RESTART;
#endif
  sigaction (signal, &sig, &ret->oldsig);
  return ret;
}

void
GNUNET_signal_handler_uninstall (int signal,
                                 GNUNET_SignalHandler handler,
                                 struct GNUNET_SignalHandlerContext *ctx)
{
  struct sigaction sig;

  GNUNET_GE_ASSERT (NULL, (ctx->sig == signal) && (ctx->method == handler));
  sigemptyset (&sig.sa_mask);
  sigaction (signal, &ctx->oldsig, &sig);
  GNUNET_free (ctx);
}
#endif

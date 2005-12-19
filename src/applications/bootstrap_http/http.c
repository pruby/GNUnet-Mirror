/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file bootstrap_http/http.c
 * @brief HOSTLISTURL support.  Downloads hellos via http.
 *
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_bootstrap_service.h"
#include "gnunet_stats_service.h"

#define DEBUG_HTTP NO

#define TCP_HTTP_PORT 80
#define HTTP_URL "http://"
#define GET_COMMAND "GET http://%s:%u%s HTTP/1.0\r\n\r\n"

/**
 * The HTTP proxy (optional)
 */
static struct sockaddr_in theProxy;

/**
 * Stats service (maybe NULL!)
 */
static Stats_ServiceAPI * stats;

static CoreAPIForApplication * coreAPI;

static int stat_hellodownloaded;

/**
 * Download hostlist from the web and call method
 * on each hello.
 */
static void
downloadHostlistHelper(char * url,
		       hello_Callback callback,
		       void * arg) {
  unsigned short port;
  char * hostname;
  char * filename;
  unsigned int curpos, lenHostname, lenUrl;
  struct hostent *ip_info;
  struct sockaddr_in soaddr;
  int sock;
  size_t ret;
  int success;
  char * command;
  cron_t start;
  char c;
  char * buffer;
  size_t n;

  port = TCP_HTTP_PORT;

  if (0 != strncmp(HTTP_URL, url, strlen(HTTP_URL)) ) {
    LOG(LOG_WARNING,
	_("Invalid URL `%s' (must begin with `%s')\n"),
	url,
	HTTP_URL);
    return;
  }
  curpos = strlen(HTTP_URL);
  hostname = &url[curpos];
  lenUrl = strlen(url);
  while ( (curpos < lenUrl) &&
	  (url[curpos] != '/') )
    curpos++;
  if (curpos == lenUrl)
    filename = STRDUP("/");
  else
    filename = STRDUP(&url[curpos]);
  url[curpos] = '\0'; /* terminator for hostname */

  curpos = 0;
  lenHostname = strlen(hostname);
  while ( (curpos < lenHostname) &&
          (hostname[curpos] != ':') )
    curpos++;
  if (curpos == lenHostname)
    port = TCP_HTTP_PORT;
  else {
    port = atoi(hostname + curpos + 1);
    if (!port) {
    	LOG(LOG_WARNING,
    		_("Invalid port \"%s\" in hostlist specification, trying port %d.\n"),
    		TCP_HTTP_PORT);
    	port = TCP_HTTP_PORT;
    }
  }

  hostname[curpos] = '\0'; /* terminator for hostname */

  sock = SOCKET(PF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    LOG(LOG_ERROR,
	_("`%s' failed at %s:%d with error: `%s'.\n"),
	"socket",
	__FILE__, __LINE__,
	STRERROR(errno));
    FREE(filename);
    return;
  }

  /* Do we need to connect through a proxy? */
  if (theProxy.sin_addr.s_addr == 0) {
    ip_info = GETHOSTBYNAME(hostname);
    if (ip_info == NULL) {
      LOG(LOG_WARNING,
	  _("Could not download list of peer contacts, host `%s' unknown.\n"),
	  hostname);
      FREE(filename);
      return;
    }

    soaddr.sin_addr.s_addr
      = ((struct in_addr*)(ip_info->h_addr))->s_addr;
    soaddr.sin_port
      = htons(port);
  } else {
    soaddr.sin_addr.s_addr
      = theProxy.sin_addr.s_addr;
    soaddr.sin_port
      = theProxy.sin_port;
  }
  soaddr.sin_family = AF_INET;

  if (CONNECT(sock,
	      (struct sockaddr*)&soaddr,
	      sizeof(soaddr)) < 0) {
    LOG(LOG_WARNING,
	_("`%s' to `%s' failed at %s:%d with error: %s\n"),
	"connect",
	hostname,
	__FILE__, __LINE__,
	STRERROR(errno));
    FREE(filename);
    closefile(sock);
    return;
  }

	/* 10: 1 + sizeof(port) */
  n = strlen(filename) + strlen(GET_COMMAND) + lenHostname + 10;
  command = MALLOC(n);
  SNPRINTF(command,
	   n,
	   GET_COMMAND,
	   hostname,
	   port,
	   filename);
  FREE(filename);
  curpos = strlen(command)+1;
  curpos = SEND_BLOCKING_ALL(sock,
			     command,
			     curpos);
  if (SYSERR == (int)curpos) {
    LOG(LOG_WARNING,
	_("`%s' to `%s' failed at %s:%d with error: %s\n"),
	"send",
	hostname,
	__FILE__, __LINE__,
	STRERROR(errno));
    FREE(command);
    closefile(sock);
    return;
  }
  FREE(command);
  cronTime(&start);

  /* we first have to read out the http_response*/
  /* it ends with four line delimiters: "\r\n\r\n" */
  curpos = 0;
  while (curpos < 4) {
    if (start + 300 * cronSECONDS < cronTime(NULL))
      break; /* exit after 5m */
    success = RECV_NONBLOCKING(sock,
			       &c,
			       sizeof(c),
			       &ret);
    if (success == NO) {
      gnunet_util_sleep(100 * cronMILLIS);
      continue;
    }
    if (ret <= 0)
      break; /* end of transmission or error */
    if ((c=='\r') || (c=='\n'))
      curpos += ret;
    else
      curpos=0;
  }

  if (curpos < 4) { /* we have not found it */
    LOG(LOG_WARNING,
	_("Parsing HTTP response for URL `%s' failed.\n"),
	url);
    closefile(sock);
    return;
  }

  buffer = MALLOC(MAX_BUFFER_SIZE);
  while (1) {
    P2P_hello_MESSAGE * helo;

    helo = (P2P_hello_MESSAGE*) &buffer[0];
    helo->header.type = htons(p2p_PROTO_hello);

    if (start + 300 * cronSECONDS < cronTime(NULL))
      break; /* exit after 300s */
    curpos = 0;
    helo->senderAddressSize = 0;
    while (curpos < P2P_hello_MESSAGE_size(helo)) {
      if (start + 300 * cronSECONDS < cronTime(NULL))
	break; /* exit after 300s */
      success = RECV_NONBLOCKING(sock,
			         &((char*)helo)[curpos],
			         P2P_hello_MESSAGE_size(helo)-curpos,
			         &ret);
      if ( success == NO )
	continue;
      if (ret <= 0)
	break; /* end of file or error*/
      if (P2P_hello_MESSAGE_size(helo) >= MAX_BUFFER_SIZE)
	break; /* INVALID! Avoid overflow! */
      curpos += ret;
    }
    if (curpos != P2P_hello_MESSAGE_size(helo)) {
      if (curpos != 0)
	LOG(LOG_WARNING,
	    _("Parsing hello from `%s' failed.\n"),
	    url);
      break;
    }
    helo->header.size = htons(P2P_hello_MESSAGE_size(helo));
    if (stats != NULL)
      stats->change(stat_hellodownloaded,
		    1);
    callback(helo,
	     arg);
  }

  FREE(buffer);
  closefile(sock);
}


static void downloadHostlist(hello_Callback callback,
			     void * arg) {
  char * url;
  int i;
  int cnt;

  url = getConfigurationString("GNUNETD",
			       "HOSTLISTURL");
  if (url == NULL) {
    LOG(LOG_DEBUG,
        "No hostlist URL specified in configuration, will not bootstrap.\n");
    return;
  }
#if DEBUG_HTTP
  LOG(LOG_DEBUG,
      "Trying to bootstrap with peers from `%s'\n",
      url);
#endif
  cnt = 1;
  i = strlen(url);
  while (i > 0) {
    i--;
    if (url[i] == ' ')
      cnt++;
  }
  cnt = weak_randomi(cnt); /* pick random hostlist of the pack */
  i = strlen(url);
  while (i > 0) {
    i--;
    if (url[i] == ' ') {
      if (cnt > 0) {
	url[i] = '\0';
	cnt--;
	continue;
      }
      downloadHostlistHelper(&url[i+1],
			     callback,
			     arg);
      FREE(url);
      return;
    }
  }
  downloadHostlistHelper(&url[0],
			 callback,
			 arg);
  FREE(url);
}


Bootstrap_ServiceAPI *
provide_module_bootstrap(CoreAPIForApplication * capi) {
  static Bootstrap_ServiceAPI api;
  char *proxy, *proxyPort;
  struct hostent *ip;

  proxy = getConfigurationString("GNUNETD",
				 "HTTP-PROXY");
  if (proxy != NULL) {
    ip = GETHOSTBYNAME(proxy);
    if (ip == NULL) {
      LOG(LOG_ERROR,
	  _("Could not resolve name of HTTP proxy `%s'. Trying without a proxy.\n"),
	  proxy);
      theProxy.sin_addr.s_addr = 0;
    } else {
      theProxy.sin_addr.s_addr
	= ((struct in_addr *)ip->h_addr)->s_addr;
      proxyPort = getConfigurationString("GNUNETD",
					 "HTTP-PROXY-PORT");
      if (proxyPort == NULL) {
	theProxy.sin_port = htons(8080);
      } else {
	theProxy.sin_port = htons(atoi(proxyPort));
	FREE(proxyPort);
      }
    }
    FREE(proxy);
  } else {
    theProxy.sin_addr.s_addr = 0;
  }

  coreAPI = capi;
  stats = coreAPI->requestService("stats");
  if (stats != NULL) {
    stat_hellodownloaded
      = stats->create(gettext_noop("# hellos downloaded via http"));
  }
  api.bootstrap = &downloadHostlist;
  return &api;
}

void release_module_bootstrap() {
  if (stats != NULL)
    coreAPI->releaseService(stats);
  coreAPI = NULL;
}

/* end of http.c */

/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @brief HOSTLISTURL support.  Downloads HELOs via http.
 *
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_bootstrap_service.h"

#define TCP_HTTP_PORT 80
#define HTTP_URL "http://"
#define GET_COMMAND "GET http://%s%s HTTP/1.0\r\n\r\n"

/**
 * The HTTP proxy (optional)
 */
static struct sockaddr_in theProxy;


/**
 * Download hostlist from the web and call method
 * on each HELO.
 */
static void
downloadHostlistHelper(char * url,
		       HELO_Callback callback,
		       void * arg) {
  unsigned short port;
  char * hostname;
  char * filename;
  unsigned int curpos;
  struct hostent *ip_info;
  struct sockaddr_in soaddr;
  int sock;
  int ret, success;
  char * command;
  cron_t start;
  char c;
  char * buffer;
  size_t n;

  port = TCP_HTTP_PORT;

  if (0 != strncmp(HTTP_URL, url, strlen(HTTP_URL)) ) {
    LOG(LOG_WARNING,
	_("Invalid URL '%s' (must begin with '%s')\n"),
	url,
	HTTP_URL);
    return;
  }
  curpos = strlen(HTTP_URL);
  hostname = &url[curpos];
  while ( (curpos < strlen(url)) &&
	  (url[curpos] != '/') )
    curpos++;
  if (curpos == strlen(url))
    filename = STRDUP("/");
  else
    filename = STRDUP(&url[curpos]);
  url[curpos] = '\0'; /* terminator for hostname */

  sock = SOCKET(PF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    LOG(LOG_ERROR,
	_("'%s' failed at %s:%d with error: '%s'.\n"),
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
	  _("Could not download list of peer contacts, host '%s' unknown.\n"),
	  hostname);
      FREE(filename);
      return;
    }

    soaddr.sin_addr.s_addr
      = ((struct in_addr*)(ip_info->h_addr))->s_addr;
    soaddr.sin_port
      = htons(TCP_HTTP_PORT);
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
	_("'%s' to '%s' failed at %s:%d with error: %s\n"),
	"connect",
	hostname,
	__FILE__, __LINE__,
	STRERROR(errno));
    FREE(filename);
    CLOSE(sock);
    return;
  }

  n = strlen(filename) + strlen(GET_COMMAND) + strlen(hostname) + 1;
  command = MALLOC(n);
  SNPRINTF(command,
	   n,
	   GET_COMMAND,
	   hostname,
	   filename);
  FREE(filename);
  curpos = strlen(command)+1;
  curpos = SEND_BLOCKING_ALL(sock,
			     command,
			     curpos);
  if (SYSERR == (int)curpos) {
    LOG(LOG_WARNING,
	_("'%s' to '%s' failed at %s:%d with error: %s\n"),
	"send",
	hostname,
	__FILE__, __LINE__,
	STRERROR(errno));
    FREE(command);
    CLOSE(sock);
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
	_("Parsing HTTP response for URL '%s' failed.\n"),
	url);
    CLOSE(sock);
    return;
  }

  buffer = MALLOC(MAX_BUFFER_SIZE);
  while (1) {
    HELO_Message * helo;

    helo = (HELO_Message*) &buffer[0];
    helo->header.type = htons(p2p_PROTO_HELO);

    if (start + 300 * cronSECONDS < cronTime(NULL))
      break; /* exit after 300s */
    curpos = 0;
    helo->senderAddressSize = 0;
    while (curpos < HELO_Message_size(helo)) {
      if (start + 300 * cronSECONDS < cronTime(NULL))
	break; /* exit after 300s */
      success = RECV_NONBLOCKING(sock,
			         &((char*)helo)[curpos],
			         HELO_Message_size(helo)-curpos,
			         &ret);
      if ( success == NO )
	continue;
      if (ret <= 0)
	break; /* end of file or error*/
      if (HELO_Message_size(helo) >= MAX_BUFFER_SIZE)
	break; /* INVALID! Avoid overflow! */
      curpos += ret;
    }
    if (curpos != HELO_Message_size(helo)) {
      if (curpos != 0)
	LOG(LOG_WARNING,
	    _("Parsing HELO from '%s' failed.\n"),
	    url);
      break;
    }
    helo->header.size = htons(HELO_Message_size(helo));
    callback(helo,
	     arg);
  }

  FREE(buffer);
  CLOSE(sock);
}


static void downloadHostlist(HELO_Callback callback,
			     void * arg) {
  char * url;
  int i;
  int cnt;

  url = getConfigurationString("GNUNETD",
			       "HOSTLISTURL");
  if (url == NULL)
    return;
  cnt = 1;
  i = strlen(url);
  while (i > 0) {
    i--;
    if (url[i] == ' ')
      cnt++;
  }
  cnt = randomi(cnt); /* pick random hostlist of the pack */
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
	  _("Could not resolve name of HTTP proxy '%s'. Trying without a proxy.\n"),
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

  api.bootstrap = &downloadHostlist;
  return &api;
}

void release_module_bootstrap() {
}

/* end of http.c */

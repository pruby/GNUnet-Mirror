/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/testing/testingtest.c
 * @brief testcase for testing library
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_testing_lib.h"

static void updatePort(struct GC_Configuration *cfg,
		       const char * section,
		       unsigned short offset) {
  unsigned long long old;

  if ( (YES == GC_have_configuration_value(cfg,
					   section,
					   "PORT")) &&
       (0 == GC_get_configuration_value_number(cfg,
					       section,
					       "PORT",
					       0,
					       65535,
					       65535,
					       &old)) ) {
    old += offset;
    GE_ASSERT(NULL,
	      0 == GC_set_configuration_value_number(cfg,
						     NULL,
						     section,
						     "PORT",
						     old));
  }
}

/**
 * Starts a gnunet daemon.
 *
 * @param app_port port to listen on for local clients
 * @param tra_offset offset to add to transport ports
 * @param gnunetd_home directory to use for the home directory
 * @param transports transport services that should be loaded
 * @param applications application services that should be loaded
 * @param pid of the process (set)
 * @param peer identity of the peer (set)
 * @return OK on success, SYSERR on error
 */
int gnunet_testing_start_daemon(unsigned short app_port,
				unsigned short tra_offset,
				const char * gnunetd_home,
				const char * transports,
				const char * applications,
				pid_t * pid,
				PeerIdentity * peer) {
  int ret;
  char * ipath;
  char * dpath;
  struct GC_Configuration * cfg;
  char host[128];
  struct ClientServerConnection * sock;
  P2P_hello_MESSAGE * hello;

  disk_directory_remove(NULL, gnunetd_home);
  ipath = os_get_installation_path(IPK_DATADIR);
  if (ipath == NULL)
    return SYSERR;
  dpath = MALLOC(strlen(ipath) + 128);
  strcpy(dpath, ipath);
  FREE(ipath);
  strcat(dpath, DIR_SEPARATOR_STR "gnunet-testing.conf");
  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   dpath)) {
    GC_free(cfg);
    FREE(dpath);
    return SYSERR;
  }
  FREE(dpath);
  updatePort(cfg, "TCP", tra_offset);
  updatePort(cfg, "TCP6", tra_offset);
  updatePort(cfg, "UDP", tra_offset);
  updatePort(cfg, "UDP6", tra_offset);
  updatePort(cfg, "HTTP", tra_offset);
  updatePort(cfg, "SMTP", tra_offset);
  GC_set_configuration_value_string(cfg,	
				    NULL,
				    "PATHS",
				    "GNUNETD_HOME",
				    gnunetd_home);
  if (transports != NULL)
    GC_set_configuration_value_string(cfg,	
				      NULL,
				      "GNUNETD",
				      "TRANSPORTS",
				      transports);
  if (applications != NULL)
    GC_set_configuration_value_string(cfg,
				      NULL,
				      "GNUNETD",
				      "APPLICATIONS",
				      applications);
  GC_set_configuration_value_number(cfg,
				    NULL,
				    "NETWORK",
				    "PORT",
				    app_port);
  dpath = STRDUP("/tmp/gnunet-config.XXXXXX");
  ret = mkstemp(dpath);
  if (ret == -1) {
    GE_LOG_STRERROR_FILE(NULL,
                         GE_ERROR | GE_USER | GE_BULK,
                         "mkstemp",
			 dpath);
    FREE(dpath);
    GC_free(cfg);
    return SYSERR;
  }
  CLOSE(ret);  
  if (0 != GC_write_configuration(cfg,
				  dpath)) {
    FREE(dpath);
    GC_free(cfg);
    return SYSERR;
  }  
  GC_free(cfg);

  cfg = GC_create_C_impl();
  /* cfg is now client CFG for os_daemon_start */
  SNPRINTF(host,
	   128,
	   "localhost:%u",
	   app_port);
  GC_set_configuration_value_string(cfg,
				    NULL,
				    "NETWORK",
				    "HOST",
				    host);

  ret = os_daemon_start(NULL,
			cfg,
			dpath,
			NO);
  if (ret == -1) {
    GC_free(cfg);
    return SYSERR; 
  } 
  *pid = ret;

  /* now get peer ID */
  if (OK != connection_wait_for_running(NULL,
					cfg,
					30 * cronSECONDS)) {
    GC_free(cfg);
    UNLINK(dpath);
    FREE(dpath);
    return SYSERR;
  }
  // UNLINK(dpath);
  FREE(dpath);
  sock = client_connection_create(NULL,
				  cfg);
  ret = gnunet_identity_get_self(sock,
				 &hello);
  if (ret == OK) {
    hash(&hello->publicKey,
	 sizeof(PublicKey),
	 &peer->hashPubKey);
    FREE(hello);
  }
  connection_destroy(sock);
  GC_free(cfg);

  return ret;
}

/**
 * Establish a connection between two GNUnet daemons
 * (both must run on this machine).
 * 
 * @param port1 client port of the first daemon
 * @param port2 client port of the second daemon
 * @return OK on success, SYSERR on failure
 */
int gnunet_testing_connect_daemons(unsigned short port1,
				   unsigned short port2) {
  char host[128];
  GC_Configuration * cfg1 = GC_create_C_impl();
  GC_Configuration * cfg2 = GC_create_C_impl();
  struct ClientServerConnection * sock1;
  struct ClientServerConnection * sock2;
  int ret;
  P2P_hello_MESSAGE * h1;
  P2P_hello_MESSAGE * h2;

  ret = SYSERR;
  SNPRINTF(host,
	   128,
	   "localhost:%u",
	   port1);
  GC_set_configuration_value_string(cfg1,
				    NULL,
				    "NETWORK",
				    "HOST",
				    host);
  SNPRINTF(host,
	   128,
	   "localhost:%u",
	   port2);
  GC_set_configuration_value_string(cfg2,
				    NULL,
				    "NETWORK",
				    "HOST",
				    host);
  if ( (OK == connection_wait_for_running(NULL,
					  cfg1,
					  30 * cronSECONDS) ) &&
       (OK == connection_wait_for_running(NULL,
					  cfg2,
					  30 * cronSECONDS) ) ) {    
    sock1 = client_connection_create(NULL,
				     cfg1);
    sock2 = client_connection_create(NULL,
				     cfg2);
    h1 = NULL;
    h2 = NULL;
    if ( (OK == gnunet_identity_get_self(sock1,
					 &h1)) &&
	 (OK == gnunet_identity_get_self(sock2,
					 &h2)) &&
	 (OK == gnunet_identity_peer_add(sock1,
					 h2)) &&
	 (OK == gnunet_identity_peer_add(sock2,
					 h1)) ) {
      ret = 10;
      while (ret-- >= 0) {
	if (YES == gnunet_identity_request_connect(sock1,
						   &h2->senderIdentity)) {
	  ret = OK;
	  break;
	}
	PTHREAD_SLEEP(2 * cronSECONDS);
      }
    }
    FREENONNULL(h1);
    FREENONNULL(h2);
    connection_destroy(sock1);
    connection_destroy(sock2);
  } else {
    fprintf(stderr,
	    "Failed to establish connection with peers.\n");
  }
  return ret;
}


/**
 * Shutdown the GNUnet daemon waiting on the given port
 * and running under the given pid.
 *
 * @return OK on success, SYSERR on failure
 */
int gnunet_testing_stop_daemon(unsigned short port,
			       pid_t pid) {
  if (os_daemon_stop(NULL, pid) != YES)
    return SYSERR;
  return OK;
}

/* end of testing.c */

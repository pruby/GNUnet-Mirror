/**
 * @file util.h Utility Functions
 * @ingroup core
 *
 * gaim
 *
 * Gaim is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * @todo Rename the functions so that they live somewhere in the gaim
 *       namespace.
 */
#ifndef _GAIM_UTIL_H_
#define _GAIM_UTIL_H_

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _GaimUtilFetchUrlData GaimUtilFetchUrlData;


/**
 * This is the signature used for functions that act as the callback
 * to gaim_util_fetch_url() or gaim_util_fetch_url_request().
 *
 * @param url_data      The same value that was returned when you called
 *                      gaim_fetch_url() or gaim_fetch_url_request().
 * @param user_data     The user data that your code passed into either
 *                      gaim_util_fetch_url() or gaim_util_fetch_url_request().
 * @param url_text      This will be NULL on error.  Otherwise this
 *                      will contain the contents of the URL.
 * @param len           0 on error, otherwise this is the length of buf.
 * @param error_message If something went wrong then this will contain
 *                      a descriptive error message, and buf will be
 *                      NULL and len will be 0.
 */
typedef void (*GaimUtilFetchUrlCallback)(GaimUtilFetchUrlData *url_data, gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message);



/**
 * Unescapes HTML entities to their literal characters.
 * For example "&amp;" is replaced by '&' and so on.
 * Actually only "&amp;", "&quot;", "&lt;" and "&gt;" are currently
 * supported.
 *
 * @param html The string in which to unescape any HTML entities
 *
 * @return the text with HTML entities literalized
 */
char *gaim_unescape_html(const char *html);


/**
 * Parses a URL, returning its host, port, file path, username and password.
 *
 * The returned data must be freed.
 *
 * @param url      The URL to parse.
 * @param ret_host The returned host.
 * @param ret_port The returned port.
 * @param ret_path The returned path.
 * @param ret_user The returned username.
 * @param ret_passwd The returned password.
 */
gboolean gaim_url_parse(const char *url, char **ret_host, int *ret_port,
						char **ret_path, char **ret_user, char **ret_passwd);



/**
 * Compares two strings to see if the first contains the second as
 * a proper prefix.
 *
 * @param s  The string to check.
 * @param p  The prefix in question.
 *
 * @return   TRUE if p is a prefix of s, otherwise FALSE.
 */
gboolean gaim_str_has_prefix(const char *s, const char *p);

/**
 * Fetches the data from a URL, and passes it to a callback function.
 *
 * @param url        The URL.
 * @param full       TRUE if this is the full URL, or FALSE if it's a
 *                   partial URL.
 * @param user_agent The user agent field to use, or NULL.
 * @param http11     TRUE if HTTP/1.1 should be used to download the file.
 * @param request    A HTTP request to send to the server instead of the
 *                   standard GET
 * @param include_headers
 *                   If TRUE, include the HTTP headers in the response.
 * @param callback   The callback function.
 * @param data       The user data to pass to the callback function.
 */
GaimUtilFetchUrlData *gaim_util_fetch_url_request(const gchar *url,
		gboolean full, const gchar *user_agent, gboolean http11,
		const gchar *request, gboolean include_headers,
		GaimUtilFetchUrlCallback callback, gpointer data);


#ifdef __cplusplus
}
#endif

#endif

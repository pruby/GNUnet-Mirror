/*
 * @file util.h Utility Functions
 * @ingroup core
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
 */

#include "platform.h"
#include "util.h"
#include <glib.h>

/* Returns a NULL-terminated string after unescaping an entity
 * (eg. &amp;, &lt; &#38 etc.) starting at s. Returns NULL on failure.*/
static const char *
detect_entity(const char *text, int *length)
{
	const char *pln;
	int len, pound;

	if (!text || *text != '&')
		return NULL;

#define IS_ENTITY(s)  (!g_ascii_strncasecmp(text, s, (len = sizeof(s) - 1)))

	if(IS_ENTITY("&amp;"))
		pln = "&";
	else if(IS_ENTITY("&lt;"))
		pln = "<";
	else if(IS_ENTITY("&gt;"))
		pln = ">";
	else if(IS_ENTITY("&nbsp;"))
		pln = " ";
	else if(IS_ENTITY("&copy;"))
		pln = "\302\251";      /* or use g_unichar_to_utf8(0xa9); */
	else if(IS_ENTITY("&quot;"))
		pln = "\"";
	else if(IS_ENTITY("&reg;"))
		pln = "\302\256";      /* or use g_unichar_to_utf8(0xae); */
	else if(IS_ENTITY("&apos;"))
		pln = "\'";
	else if(*(text+1) == '#' && (sscanf(text, "&#%u;", &pound) == 1) &&
			pound != 0 && *(text+3+(gint)log10(pound)) == ';') {
		static char buf[7];
		int buflen = g_unichar_to_utf8((gunichar)pound, buf);
		buf[buflen] = '\0';
		pln = buf;

		len = 2;
		while(isdigit((gint) text[len])) len++;
		if(text[len] == ';') len++;
	}
	else
		return NULL;

	if (length)
		*length = len;
	return pln;
}

char *
gaim_unescape_html(const char *html) {
	if (html != NULL) {
		const char *c = html;
		GString *ret = g_string_new("");
		while (*c) {
			int len;
			const char *ent;

			if ((ent = detect_entity(c, &len)) != NULL) {
				ret = g_string_append(ret, ent);
				c += len;
			} else if (!strncmp(c, "<br>", 4)) {
				ret = g_string_append_c(ret, '\n');
				c += 4;
			} else {
				ret = g_string_append_c(ret, *c);
				c++;
			}
		}
		return g_string_free(ret, FALSE);
	}

	return NULL;
}


/**************************************************************************
 * URI/URL Functions
 **************************************************************************/
gboolean
gaim_url_parse(const char *url, char **ret_host, int *ret_port,
			   char **ret_path, char **ret_user, char **ret_passwd)
{
	char scan_info[255];
	char port_str[6];
	int f;
	const char *at, *slash;
	const char *turl;
	char host[256], path[256], user[256], passwd[256];
	int port = 0;
	/* hyphen at end includes it in control set */
	static char addr_ctrl[] = "A-Za-z0-9.-";
	static char port_ctrl[] = "0-9";
	static char page_ctrl[] = "A-Za-z0-9.~_/:*!@&%%?=+^-";
	static char user_ctrl[] = "A-Za-z0-9.~_/*!&%%?=+^-";
	static char passwd_ctrl[] = "A-Za-z0-9.~_/*!&%%?=+^-";

	g_return_val_if_fail(url != NULL, FALSE);

	if ((turl = strstr(url, "http://")) != NULL ||
		(turl = strstr(url, "HTTP://")) != NULL)
	{
		turl += 7;
		url = turl;
	}

	/* parse out authentication information if supplied */
	/* Only care about @ char BEFORE the first / */
	at = strchr(url, '@');
	slash = strchr(url, '/');
	if ((at != NULL) &&
			(((slash != NULL) && (strlen(at) > strlen(slash))) ||
			(slash == NULL))) {
		g_snprintf(scan_info, sizeof(scan_info),
					"%%255[%s]:%%255[%s]^@", user_ctrl, passwd_ctrl);
		f = sscanf(url, scan_info, user, passwd);

		if (f ==1 ) {
			/* No passwd, possibly just username supplied */
			g_snprintf(scan_info, sizeof(scan_info),
						"%%255[%s]^@", user_ctrl);
			f = sscanf(url, scan_info, user);
			*passwd = '\0';
		}

		url = at+1; /* move pointer after the @ char */
	} else {
		*user = '\0';
		*passwd = '\0';
	}

	g_snprintf(scan_info, sizeof(scan_info),
			   "%%255[%s]:%%5[%s]/%%255[%s]", addr_ctrl, port_ctrl, page_ctrl);

	f = sscanf(url, scan_info, host, port_str, path);

	if (f == 1)
	{
		g_snprintf(scan_info, sizeof(scan_info),
				   "%%255[%s]/%%255[%s]",
				   addr_ctrl, page_ctrl);
		f = sscanf(url, scan_info, host, path);
		g_snprintf(port_str, sizeof(port_str), "80");
	}

	if (f == 1)
		*path = '\0';

	sscanf(port_str, "%d", &port);

	if (ret_host != NULL) *ret_host = g_strdup(host);
	if (ret_port != NULL) *ret_port = port;
	if (ret_path != NULL) *ret_path = g_strdup(path);
	if (ret_user != NULL) *ret_user = g_strdup(user);
	if (ret_passwd != NULL) *ret_passwd = g_strdup(passwd);

	return TRUE;
}


gaim_str_has_prefix(const char *s, const char *p)
{
#if GLIB_CHECK_VERSION(2,2,0)
        return g_str_has_prefix(s, p);
#else
        g_return_val_if_fail(s != NULL, FALSE);
        g_return_val_if_fail(p != NULL, FALSE);

        return (!strncmp(s, p, strlen(p)));
#endif
}

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
						  GaimUtilFetchUrlCallback callback, gpointer data) {
  /* FIXME: implement using libcurl? */
  return NULL;
}


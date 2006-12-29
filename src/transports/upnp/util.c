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


gboolean
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



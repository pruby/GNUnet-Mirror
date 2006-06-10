/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

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
/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 * Released under the terms of the GNU GPL v2.0.
 */

/**
 * @file conf/conf.c
 * @brief GNUnet Setup
 * @author Roman Zippel
 * @author Nils Durner
 */

#define LKC_DIRECT_LINK
#include "lkc.h"

#include "confdata.h"

static void conf(struct menu *menu);
static void check_conf(struct menu *menu);

enum {
	ask_all,
	ask_new,
	ask_silent,
	set_default,
	set_yes,
	set_mod,
	set_no,
	set_random
} input_mode = ask_all;
char *defconfig_file;

static int indent = 1;
static int valid_stdin = 1;
static int conf_cnt;
static char line[128];
static struct menu *rootEntry;

static char nohelp_text[] = "Sorry, no help available for this option yet.\n";

static void strip(char *str)
{
	char *p = str;
	int l;

	while ((isspace(*p)))
		p++;
	l = strlen(p);
	if (p != str)
		memmove(str, p, l + 1);
	if (!l)
		return;
	p = str + l - 1;
	while ((isspace(*p)))
		*p-- = 0;
}

static void check_stdin(void)
{
	if (!valid_stdin && input_mode == ask_silent) {
		printf("aborted!\n\n");
		printf("Console input/output is redirected. ");
		printf("Run 'make oldconfig' to update configuration.\n\n");
		exit(1);
	}
}

static void conf_askvalue(struct symbol *sym, const char *def)
{
	enum symbol_type type = sym_get_type(sym);
	tristate val;

	if (!sym_has_value(sym))
		printf("(NEW) ");

	line[0] = '\n';
	line[1] = 0;

	if (!sym_is_changable(sym)) {
		printf("%s\n", def);
		line[0] = '\n';
		line[1] = 0;
		return;
	}

	switch (input_mode) {
	case ask_new:
	case ask_silent:
		if (sym_has_value(sym)) {
			printf("%s\n", def);
			return;
		}
		check_stdin();
	case ask_all:
		fflush(stdout);
		fgets(line, 128, stdin);
		return;
	case set_default:
		printf("%s\n", def);
		return;
	default:
		break;
	}

	switch (type) {
	case S_INT:
	case S_HEX:
	case S_STRING:
		printf("%s\n", def);
		return;
	default:
		;
	}
	switch (input_mode) {
	case set_yes:
		if (sym_tristate_within_range(sym, yes)) {
			line[0] = 'y';
			line[1] = '\n';
			line[2] = 0;
			break;
		}
	case set_mod:
		if (type == S_TRISTATE) {
			if (sym_tristate_within_range(sym, mod)) {
				line[0] = 'm';
				line[1] = '\n';
				line[2] = 0;
				break;
			}
		} else {
			if (sym_tristate_within_range(sym, yes)) {
				line[0] = 'y';
				line[1] = '\n';
				line[2] = 0;
				break;
			}
		}
	case set_no:
		if (sym_tristate_within_range(sym, no)) {
			line[0] = 'n';
			line[1] = '\n';
			line[2] = 0;
			break;
		}
	case set_random:
		do {
			val = (tristate)(rand() % 3);
		} while (!sym_tristate_within_range(sym, val));
		switch (val) {
		case no: line[0] = 'n'; break;
		case mod: line[0] = 'm'; break;
		case yes: line[0] = 'y'; break;
		}
		line[1] = '\n';
		line[2] = 0;
		break;
	default:
		break;
	}
	printf("%s", line);
}

int conf_string(struct menu *menu)
{
	struct symbol *sym = menu->sym;
	const char *def, *help;

	while (1) {
		printf("%*s%s ", indent - 1, "", menu->prompt->text);
		printf("(%s) ", sym->name);
		def = sym_get_string_value(sym);
		if (sym_get_string_value(sym))
			printf("[%s] ", def);
		conf_askvalue(sym, def);
		switch (line[0]) {
		case '\n':
			break;
		case '?':
			/* print help */
			if (line[1] == 0) {
				help = nohelp_text;
				if (menu->sym->help)
					help = menu->sym->help;
				printf("\n%s\n", menu->sym->help);
				def = NULL;
				break;
			}
		default:
			line[strlen(line)-1] = 0;
			def = line;
		}
		if (def && sym_set_string_value(sym, def))
			return 0;
	}
}

static int conf_sym(struct menu *menu)
{
	struct symbol *sym = menu->sym;
	int type;
	tristate oldval, newval;
	const char *help;

	while (1) {
		printf("%*s%s ", indent - 1, "", menu->prompt->text);
		if (sym->name)
			printf("(%s) ", sym->name);
		type = sym_get_type(sym);
		putchar('$');
		oldval = sym_get_tristate_value(sym);
		switch (oldval) {
		case no:
			putchar('N');
			break;
		case mod:
			putchar('M');
			break;
		case yes:
			putchar('Y');
			break;
		}
		if (oldval != no && sym_tristate_within_range(sym, no))
			printf("/n");
		if (oldval != mod && sym_tristate_within_range(sym, mod))
			printf("/m");
		if (oldval != yes && sym_tristate_within_range(sym, yes))
			printf("/y");
		if (sym->help)
			printf("/?");
		printf("] ");
		conf_askvalue(sym, sym_get_string_value(sym));
		strip(line);

		switch (line[0]) {
		case 'n':
		case 'N':
			newval = no;
			if (!line[1] || !strcmp(&line[1], "o"))
				break;
			continue;
		case 'm':
		case 'M':
			newval = mod;
			if (!line[1])
				break;
			continue;
		case 'y':
		case 'Y':
			newval = yes;
			if (!line[1] || !strcmp(&line[1], "es"))
				break;
			continue;
		case 0:
			newval = oldval;
			break;
		case '?':
			goto help;
		default:
			continue;
		}
		if (sym_set_tristate_value(sym, newval))
			return 0;
help:
		help = nohelp_text;
		if (sym->help)
			help = sym->help;
		printf("\n%s\n", help);
	}
}

static int conf_choice(struct menu *menu)
{
	struct symbol *sym, *def_sym;
	struct menu *child;
	int type;
	bool is_new;

	sym = menu->sym;
	type = sym_get_type(sym);
	is_new = !sym_has_value(sym);
	if (sym_is_changable(sym)) {
		conf_sym(menu);
		sym_calc_value(sym);
		switch (sym_get_tristate_value(sym)) {
		case no:
			return 1;
		case mod:
			return 0;
		case yes:
			break;
		}
	} else {
		switch (sym_get_tristate_value(sym)) {
		case no:
			return 1;
		case mod:
			printf("%*s%s\n", indent - 1, "", menu_get_prompt(menu));
			return 0;
		case yes:
			break;
		}
	}

	while (1) {
		int cnt, def;

		printf("%*s%s\n", indent - 1, "", menu_get_prompt(menu));
		def_sym = sym_get_choice_value(sym);
		cnt = def = 0;
		line[0] = '0';
		line[1] = 0;
		for (child = menu->list; child; child = child->next) {
			if (!menu_is_visible(child))
				continue;
			if (!child->sym) {
				printf("%*c %s\n", indent, '*', menu_get_prompt(child));
				continue;
			}
			cnt++;
			if (child->sym == def_sym) {
				def = cnt;
				printf("%*c", indent, '>');
			} else
				printf("%*c", indent, ' ');
			printf(" %d. %s", cnt, menu_get_prompt(child));
			if (child->sym->name)
				printf(" (%s)", child->sym->name);
			if (!sym_has_value(child->sym))
				printf(" (NEW)");
			printf("\n");
		}
		printf("%*schoice", indent - 1, "");
		if (cnt == 1) {
			printf("[1]: 1\n");
			goto conf_childs;
		}
		printf("[1-%d", cnt);
		if (sym->help)
			printf("?");
		printf("]: ");
		switch (input_mode) {
		case ask_new:
		case ask_silent:
			if (!is_new) {
				cnt = def;
				printf("%d\n", cnt);
				break;
			}
			check_stdin();
		case ask_all:
			fflush(stdout);
			fgets(line, 128, stdin);
			strip(line);
			if (line[0] == '?') {
				printf("\n%s\n", menu->sym->help ?
					menu->sym->help : nohelp_text);
				continue;
			}
			if (!line[0])
				cnt = def;
			else if (isdigit(line[0]))
				cnt = atoi(line);
			else
				continue;
			break;
		case set_random:
			def = (rand() % cnt) + 1;
		case set_default:
		case set_yes:
		case set_mod:
		case set_no:
			cnt = def;
			printf("%d\n", cnt);
			break;
		}

	conf_childs:
		for (child = menu->list; child; child = child->next) {
			if (!child->sym || !menu_is_visible(child))
				continue;
			if (!--cnt)
				break;
		}
		if (!child)
			continue;
		if (line[strlen(line) - 1] == '?') {
			printf("\n%s\n", child->sym->help ?
				child->sym->help : nohelp_text);
			continue;
		}
		sym_set_choice_value(sym, child->sym);
		if (child->list) {
			indent += 2;
			conf(child->list);
			indent -= 2;
		}
		return 1;
	}
}

static void conf(struct menu *menu)
{
	struct symbol *sym;
	struct property *prop;
	struct menu *child;

	if (!menu_is_visible(menu))
		return;

	sym = menu->sym;
	prop = menu->prompt;
	if (prop) {
		const char *prompt;

		switch (prop->type) {
		case P_MENU:
			if (input_mode == ask_silent && rootEntry != menu) {
				check_conf(menu);
				return;
			}
		case P_COMMENT:
			prompt = menu_get_prompt(menu);
			if (prompt)
				printf("%*c\n%*c %s\n%*c\n",
					indent, '*',
					indent, '*', prompt,
					indent, '*');
		default:
			;
		}
	}

	if (!sym)
		goto conf_childs;

	if (sym_is_choice(sym)) {
		conf_choice(menu);
		if (sym->curr.tri != mod)
			return;
		goto conf_childs;
	}

	switch (sym->type) {
	case S_INT:
	case S_HEX:
	case S_STRING:
		conf_string(menu);
		break;
	default:
		conf_sym(menu);
		break;
	}

conf_childs:
	if (sym)
		indent += 2;
	for (child = menu->list; child; child = child->next)
		conf(child);
	if (sym)
		indent -= 2;
}

static void check_conf(struct menu *menu)
{
	struct symbol *sym;
	struct menu *child;

	if (!menu_is_visible(menu))
		return;

	sym = menu->sym;
	if (sym) {
		if (sym_is_changable(sym) && !sym_has_value(sym)) {
			if (!conf_cnt++)
				printf("*\n* Restart config...\n*\n");
			rootEntry = menu_get_parent_menu(menu);
			conf(rootEntry);
		}
		if (sym_is_choice(sym) && sym_get_tristate_value(sym) != mod)
			return;
	}

	for (child = menu->list; child; child = child->next)
		check_conf(child);
}

int conf_main()
{
  char * filename;

  filename = getConfigurationString("GNUNET-SETUP",
				    "FILENAME");
  conf_read(filename);
  input_mode = ask_all; /* for now */
  rootEntry = &rootmenu;
  conf(&rootmenu);
  do {
    conf_cnt = 0;
    check_conf(&rootmenu);
  } while (conf_cnt);

  if (conf_write(filename)) {
    printf(_("Unable to save configuration file `%s': %s.\n"),
	   filename,
	   STRERROR(errno));
    FREE(filename);
    return 1;
  }
  else {
    printf(_("Configuration file `%s' created.\n"),
	   filename);
    FREE(filename);
    return 0;
  }
}

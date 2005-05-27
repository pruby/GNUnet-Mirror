/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 * Released under the terms of the GNU GPL v2.0.
 */

/**
 * @file conf/confdata.c
 * @brief GNUnet Setup
 * @author Roman Zippel
 * @author Nils Durner
 */

#include <sys/stat.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#define LKC_DIRECT_LINK
#include "lkc.h"

#include "platform.h"
#include "gnunet_util.h"

const char conf_def_filename[] = "gnunet.conf";

const char conf_defname[] = "defconfig";

const char *conf_confnames[] = {
				".config",
        "/tmp/.config",
        "/etc/gnunet.conf",
				conf_defname,
				NULL,
};

static char *conf_expand_value(const char *in)
{
	struct symbol *sym;
	const char *src;
	static char res_value[SYMBOL_MAXLENGTH];
	char *dst, name[SYMBOL_MAXLENGTH];

	res_value[0] = 0;
	dst = name;
	while ((src = strchr(in, '$'))) {
		strncat(res_value, in, src - in);
		src++;
		dst = name;
		while (isalnum(*src) || *src == '_')
			*dst++ = *src++;
		*dst = 0;
		sym = sym_lookup(name, "X", 0);
		sym_calc_value(sym);
		strcat(res_value, sym_get_string_value(sym));
		in = src;
	}
	strcat(res_value, in);

	return res_value;
}

char *conf_get_default_confname(void)
{
	struct stat buf;
	static char fullname[PATH_MAX+1];
	char *env, *name;

	name = conf_expand_value(conf_defname);
	env = getenv(SRCTREE);
	if (env) {
		sprintf(fullname, "%s/%s", env, name);
		if (!STAT(fullname, &buf))
			return fullname;
	}
	return name;
}

void extract_setting(char *line, char **setting, char *sect)
{
	int idx = 0;
	while ((!(line[idx] == '!' || line[idx] == 0)) &&
		idx <= 250)
	{
		sect[idx] = line[idx];
		idx++;
	}
	if (! line[idx])
	{
		strcpy(sect, "GENERAL");
		idx = 0;
	}
	else
		sect[idx] = 0;

	if(idx)
		idx++;

	*setting = line + idx;
}

int conf_read(const char *name)
{
	char *val;
	struct symbol *sym;
	struct property *prop;
	struct expr *e;
	int i = 0;
	
	if (! name) {
		/* Read default config files as defined in the templates */
		if (! name && file_list) {
			struct file *f;
			i = 1;
			
			/* Go through the list of used template files */
			for (f = file_list; f; f = f->next) {
				char *path, *fn, *key;
				struct symbol *defFile;
				
				path = f->name;
				fn = path + strlen(path);
				
				/* Get filename without path */
				while(*fn != '/' && *fn != '\\' && fn != path)
					fn--;
				if (fn != path)
					fn++;
				
				/* Query default config file */
				key = malloc(strlen(fn) + 16);
				sprintf(key, "%s_CONF_DEF_DIR", fn);
				sym = sym_find(key, "Meta");
				if (sym) {
					sprintf(key, "%s_CONF_DEF_FILE", fn);
					defFile = sym_find(key, "Meta");
					if (defFile) {
						char *path, *file;
						
						sym_calc_value_ext(sym, 1);
						sym_calc_value_ext(defFile, 1);
						path = (char *) sym_get_string_value(sym);
						file = (char *) sym_get_string_value(defFile);					
						
						key = realloc(key, strlen(path) + strlen(file) + 2);
						sprintf(key, "%s%c%s", path, DIR_SEPARATOR, file);
						cfg_parse_file(key);
					}
				}
				free(key);
			}
		}

		/* Read global default files (only if necessary) */
		if (!i) {
			const char **names = conf_confnames;
			
			while ((name = *names++)) {
				name = conf_expand_value(name);
				if (cfg_parse_file((char *) name) == 0) {
					printf("#\n"
					       "# using defaults found in %s\n"
					       "#\n", name);
					i = 1;
					break;
				}
			}
		}
	}
	else {
		i = 1;
		cfg_parse_file((char *) name);
	}

	if (!i)
		return 1;
	
	for_all_symbols(i, sym) {
	  sym->flags |= SYMBOL_NEW | SYMBOL_CHANGED;
		sym->flags &= ~SYMBOL_VALID;
		
		val = cfg_get_str(sym->sect, sym->name);
		if (val) {
  		switch (sym->type) {
  			case S_TRISTATE:
  				if (*val == 'm') {
  					sym->user.tri = mod;
  					sym->flags &= ~SYMBOL_NEW;
  					break;
  				}
  			case S_BOOLEAN:
  				sym->user.tri = (*val == 'Y') ? yes : no;
  				sym->flags &= ~SYMBOL_NEW;
  				break;
  			case S_STRING:
  			case S_INT:
  			case S_HEX:
  				if (sym->user.val)
  					free(sym->user.val);
  
  				if (sym_string_valid(sym, val)) {
  					sym->user.val = strdup(val);
  					sym->flags &= ~SYMBOL_NEW;
  				}
  				else {
  					fprintf(stderr, "%s: symbol value '%s' invalid for %s\n", name, val, sym->name);
  					doneParseConfig();
  					exit(1);
  				}

  				if (!sym_string_within_range(sym, val))
  					sym->flags |= SYMBOL_NEW;

  				break;
  			default:
    			sym->user.val = NULL;
    			sym->user.tri = no;
  		}
  		
  		if (sym && sym_is_choice_value(sym)) {
  			struct symbol *cs = prop_get_symbol(sym_get_choice_prop(sym));
  			switch (sym->user.tri) {
  			case no:
  				break;
  			case mod:
  				if (cs->user.tri == yes)
  					/* warn? */;
  				break;
  			case yes:
  				if (cs->user.tri != no)
  					/* warn? */;
  				cs->user.val = sym;
  				break;
  			}
  			cs->user.tri = E_OR(cs->user.tri, sym->user.tri);
  			cs->flags &= ~SYMBOL_NEW;
  		}

  		sym_calc_value(sym);
  		if (sym_has_value(sym) && !sym_is_choice_value(sym)) {
  			if (sym->visible == no)
  				sym->flags |= SYMBOL_NEW;
  		}
  		if (!sym_is_choice(sym))
  			continue;
  		prop = sym_get_choice_prop(sym);
  		for (e = prop->expr; e; e = e->left.expr)
  			if (e->right.sym->visible != no)
  				sym->flags |= e->right.sym->flags & SYMBOL_NEW;
  	}
	}
	
	sym_change_count = 1;

	return 0;
}

int conf_write(const char *name)
{
	FILE *out = NULL;
	struct symbol *sym;
	struct menu *menu;
	const char *basename;
	char dirname[128], tmpname[128], newname[128];
	int type;
	const char *str;
	const char *cur_tmpl = NULL;
	char **tempfiles = NULL;
	int num_tempfiles = 0;
	int idx;

  sym_clear_all_valid();

	menu = rootmenu.list;
	while (menu) {

		sym = menu->sym;
		
		if (!sym) {

			str = menu_get_prompt(menu);
			if (str && strlen(str) > 0) {			
				/* First of all, we have to determine where to write the menu's settings to.
				 * There are two possibilites:
				 * 	1. There's a setting $prefix_CONF_DEF_FILE that defines the file
				 * 		 (this is useful if independent .in files with different
				 *     destination files are included together). $prefix is the name
				 *     of the template file.
				 *  2. We use conf_def_filename. */
				if (!out || (cur_tmpl == NULL || strcmp(cur_tmpl, menu->file->name) != 0)) {
					char key[251];
					struct symbol *fn_sym;
					int registered;
					char *prefix;
					struct stat stat_cf;
					int exists;
					
					/* This setting's destination file is different from the previous
					 * one's. */
					if (out)
						fclose(out);
					
					cur_tmpl = menu->file->name;
					prefix = (char *) cur_tmpl + strlen(cur_tmpl);
					while(*prefix != '/' && *prefix != '\\')
						prefix--;
					prefix++;
					
					/* Determine destination */
					SNPRINTF(key, 250, "%s_CONF_DEF_FILE", prefix);
					fn_sym = sym_find(key, "Meta");
					
					if (! fn_sym) {
						/* Default filename */
						strncpy(newname, conf_def_filename, 127);
						newname[127] = 0;
						basename = conf_def_filename;
						strcpy(dirname, "/etc/");
					}
					else
					{
						sym_calc_value_ext(fn_sym, 1);
		
						dirname[0] = 0;
						if (name && name[0]) {
							char *slash = strrchr(name, '/'); /* the path is always '/' delimited */
							if (slash) {
								int size = slash - name + 1;
								memcpy(dirname, name, size);
								dirname[size] = 0;
								if (slash[1])
									basename = slash + 1;
								else
									basename = sym_get_string_value(fn_sym);
							} else
								basename = name;
						} else
							basename = sym_get_string_value(fn_sym);
					
						if (! dirname[0]) {
							SNPRINTF(key, 250, "%s_CONF_DEF_DIR", prefix);
							fn_sym = sym_find(key, "Meta");
							
							if (fn_sym) {
								sym_calc_value_ext(fn_sym, 1);
								strcpy(dirname, sym_get_string_value(fn_sym));
							}
							else
								strcpy(dirname, "/etc/");
						}
					}
					
					/* Create a temporary filename */
					sprintf(newname,
						"%s%s-%u.tmp",
						dirname,
						basename,
						(unsigned int) getpid());
		
					exists = STAT(newname, &stat_cf);
					
					out = FOPEN(newname, "a");
					
					if (!out)
						return 1;
		
					if (exists == -1)
					  fprintf(out, "#%s"
								       	 "# Automatically generated by gnunet-setup%s"
								       	 "#%s", NEWLINE, NEWLINE, NEWLINE);
		
					/* Save the temporary filename to rename it later */
					registered = 0;
					for (idx=0; idx < num_tempfiles; idx++) {
						if (strcmp(tempfiles[idx], newname) == 0)
							registered = 1;
					}
					if (! registered) {
						if (num_tempfiles == 0)
							tempfiles = malloc(sizeof(char **));
						else
							tempfiles = realloc(tempfiles, (num_tempfiles + 1) * sizeof(char **));
						tempfiles[num_tempfiles] = strdup(newname);
						num_tempfiles++;
					}
				}

				fprintf(out, "%s"
					"#%s"
					"# %s%s"
					"#%s", NEWLINE, NEWLINE, str, NEWLINE, NEWLINE);
			}
			if (menu->section && strlen(menu->section) > 0)
				fprintf(out, "[%s]%s", menu->section, NEWLINE);
		} else if (!(sym->flags & SYMBOL_CHOICE)) {
			sym_calc_value_ext(sym, 1);
			sym->flags &= ~SYMBOL_WRITE;
			type = sym->type;
			if (type == S_TRISTATE) {
				sym_calc_value_ext(modules_sym, 1);
				if (modules_sym->curr.tri == no)
					type = S_BOOLEAN;
			}
			switch (type) {
			case S_BOOLEAN:
			case S_TRISTATE:
				switch (sym_get_tristate_value(sym)) {
				case no:
					fprintf(out, "%s = NO", sym->name);
					break;
				case mod:
					fprintf(out, "%s = m", sym->name);
					break;
				case yes:
					fprintf(out, "%s = YES", sym->name);
					break;
				}
				break;
			case S_STRING:
        fprintf(out, "%s = \"%s\"", sym->name, sym_get_string_value(sym));
				break;
			case S_HEX:
				str = sym_get_string_value(sym);
				if (str[0] != '0' || (str[1] != 'x' && str[1] != 'X')) {
					fprintf(out, "%s = 0x%s", sym->name, str);
					break;
				}
			case S_INT:
				fprintf(out, "%s = %s", sym->name, sym_get_string_value(sym));
				break;
			}
			fprintf(out, "%s", NEWLINE);
		}

		if (menu->list) {
			menu = menu->list;
			continue;
		}
		if (menu->next)
			menu = menu->next;
		else while ((menu = menu->parent)) {
			if (menu->next) {
				menu = menu->next;
				break;
			}
		}
	}
	
	if (out)
		fclose(out);
	
	for (idx=0; idx < num_tempfiles; idx++) {
		char *dstname, *tempfile;
		int dstlen;
		
		/* Get real destination name. The temporary name has the form
		 * 		name-pid.tmp */
		tempfile = tempfiles[idx];
		dstlen = strlen(tempfile);
		while (tempfile[dstlen] != '-')
			dstlen--;
		
		dstname = malloc(dstlen + 1);
		strncpy(dstname, tempfile, dstlen);
		dstname[dstlen] = 0;
		
		sprintf(tmpname, "%s.old", dstname);
		UNLINK(tmpname);
		RENAME(dstname, tmpname);

		if (RENAME(tempfile, dstname)) {
			free(dstname);
			free(tempfile);

			return 1;
		}
		
		UNLINK(tempfile);
		
		free(dstname);
		free(tempfile);
	}
	
	if (tempfiles)
		free(tempfiles);

	sym_change_count = 0;

	return 0;
}

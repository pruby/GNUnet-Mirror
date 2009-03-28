/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file gnunet-macosx-tool.c
 * @brief tool for Mac OS X specific (privileged) setup tasks
 * @author Heikki Lindholm
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include <GNUnet/gnunet_util.h>

static char * input_string()
{
	char *buf;
	int len;
	int n;
	
	n = fread(&len, sizeof(len), 1, stdin);
	if (n < 1)
		return NULL;
		
	if (len <= 0)
		return NULL;
		
	buf = malloc(len);
	n = fread(buf, 1, len, stdin);
	if (n < len) {
		free(buf);
		return NULL;
	}
	
	return buf;
}

static void output_string(char *s)
{
	int len;
	
	if (s == NULL) {
		len = 0;
		fwrite(&len, sizeof(len), 1, stdout);
		return;
	}

	len = strlen(s)+1;
	fwrite(&len, sizeof(len), 1, stdout);
	fwrite(s, 1, len, stdout);
}

static int read_config(int argc, char *argv[])
{
	const char *filename;
	struct GNUNET_GE_Context *ectx;
	struct GNUNET_GE_Memory *ectx_buffer;
	struct GNUNET_GC_Configuration *config;
	int i;
	int ret;

	filename = argv[2];
	ectx_buffer = GNUNET_GE_memory_create(2);
	ectx = GNUNET_GE_create_context_memory(GNUNET_GE_ALL, ectx_buffer);
	GNUNET_GE_setDefaultContext(ectx);
	GNUNET_os_init(ectx);
	config = GNUNET_GC_create();
	
	ret = GNUNET_GC_parse_configuration (config, filename);
	for (i = 3; i < argc; i++) {
		char *section, *option, *value;
		
		section = GNUNET_strdup(argv[i]);
		option = section;
		while (*option != '\0' && *option != ':')
			option++;
		if (option == '\0') {
			GNUNET_free(section);
			continue;
		}
		option[0] = '\0';
		option++;
		ret = GNUNET_GC_get_configuration_value_string(config, 
			section, option, NULL, &value);
		if (ret != GNUNET_SYSERR) {
			output_string(section);
			output_string(option);
			output_string(value);
			GNUNET_free(value);
		}
		GNUNET_free(section);
	}
	
	GNUNET_GC_free(config);
	GNUNET_GE_free_context(ectx);
	GNUNET_GE_memory_free(ectx_buffer);
	
	return 0;
}

static int write_config(int argc, char *argv[])
{
	const char *filename;
	struct GNUNET_GE_Context *ectx;
	struct GNUNET_GE_Memory *ectx_buffer;
	struct GNUNET_GC_Configuration *config;
	int ret;

	filename = argv[2];
	ectx_buffer = GNUNET_GE_memory_create(2);
	ectx = GNUNET_GE_create_context_memory(GNUNET_GE_ALL, ectx_buffer);
	GNUNET_GE_setDefaultContext(ectx);
	GNUNET_os_init(ectx);
	config = GNUNET_GC_create();
	
	/* parse old config first, so that options not in the scm
	 * get preserved
	 */
	ret = GNUNET_GC_parse_configuration (config, filename);
	do {
		char *section, *option, *value;
		
		section = input_string();
		if (section == NULL)
			break;
		option = input_string();
		value = input_string();
		if (section && option) {
			ret = GNUNET_GC_set_configuration_value_string(
				config, ectx, section, option, value);
				
		}
		if (section) free(section);
		if (option) free(option);
		if (value) free(value);
	} while(1);
	
	if (GNUNET_GC_write_configuration (config, filename) == 0) {
		output_string("OK");
		ret = 0;
	}
	else {
		output_string("ERROR");
		ret = -1;
	}
	
	GNUNET_GC_free(config);
	GNUNET_GE_free_context(ectx);
	GNUNET_GE_memory_free(ectx_buffer);
	
	return ret;
}
 
int create_accounts(int argc, char *argv[])
{
	char *user_name;
	char *group_name;
	int ret;

	if (argc < 3)
		return -1;
	 
	user_name = argv[2];
	if (argc < 4)
		group_name = NULL;
	else
		group_name = argv[3];
	ret = GNUNET_configure_user_account(0, 1, group_name, user_name);

	if (ret == GNUNET_OK) {
		output_string("OK");
		ret = 0;
	}
	else {
		output_string("ERROR");
		ret = -1;
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc < 3) {
		return EXIT_FAILURE;
	}
 
	if (strcmp(argv[1], "readConfig") == 0) {
		ret = read_config(argc, argv);
	}
	else if (strcmp(argv[1], "writeConfig") == 0) {
		ret = write_config(argc, argv);
	}
	else if (strcmp(argv[1], "createUserGroup") == 0) {
		ret = create_accounts(argc, argv);
	}
 
	return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}



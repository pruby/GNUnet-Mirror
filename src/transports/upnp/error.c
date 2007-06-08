
#include "error.h"

/**
 * Map gaim logger to GNUnet logger.
 */
void gaim_debug_error(char * facility,
		      char * format,
		      ...) {
 GE_LOG(NULL,
	GE_WARNING | GE_DEVELOPER | GE_ADMIN | GE_BULK,
	"%s: %s\n",
	facility,
	format);
}

/**
 * Map gaim logger to GNUnet logger.
 */
void gaim_debug_info(char * facility,
		     char * format,
		     ...) {
 GE_LOG(NULL,
	GE_INFO | GE_ADMIN | GE_BULK,
	"%s: %s\n",
	facility,
	format);
}


 /*
      This file is part of GNUnet

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

#ifndef GETOPTION_H
#define GETOPTION_H

#define CS_GET_OPTION_REQUEST_OPT_LEN 32

/**
 * Request for option value.
 */
typedef struct {
  CS_HEADER header;
  char section[CS_GET_OPTION_REQUEST_OPT_LEN];
  char option[CS_GET_OPTION_REQUEST_OPT_LEN];
} CS_GET_OPTION_REQUEST;

/**
 * Reply with option value (variable size,
 * value is 0-terminated).
 */
typedef struct {
  CS_HEADER header;
  char value[1];
} CS_GET_OPTION_REPLY;

#endif

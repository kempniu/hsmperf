/*
 * hsmperf - simple benchmarking tool for PKCS#11 providers
 *
 * Copyright (C) 2015 Michał Kępień <github@kempniu.pl>
 *
 * Inspired by: https://nlnetlabs.nl/downloads/publications/hsm/hsm.pdf
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * This program is derived from the RSA Security Inc. PKCS #11 Cryptographic
 * Token Interface (Cryptoki).
 */

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
	returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
	returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
	returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
	returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define OUT_OF_MEMORY_IF(cond) \
	if (cond) { \
		fprintf(stderr, "Out of memory at line %d\n", __LINE__); \
		exit(EXIT_FAILURE); \
	}

const char *usage_message =
	"Usage: hsmperf -l /path/to/libpkcs11.so\n";

char *pkcs11_lib_path = NULL;
void *pkcs11_lib_handle = NULL;

void
parse_options(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "l:")) != -1) {
		switch (opt) {
		case 'l':
			pkcs11_lib_path = malloc(strlen(optarg) + 1);
			OUT_OF_MEMORY_IF(!pkcs11_lib_path);
			strcpy(pkcs11_lib_path, optarg);
			break;
		default:
			fprintf(stderr, "%s", usage_message);
			exit(EXIT_FAILURE);
		}
	}

	if (!pkcs11_lib_path) {
		fprintf(stderr, "%s", usage_message);
		exit(EXIT_FAILURE);
	}
}

int
main(int argc, char *argv[])
{
	parse_options(argc, argv);

	pkcs11_lib_handle = dlopen(pkcs11_lib_path, RTLD_LAZY);
	if (!pkcs11_lib_handle) {
		fprintf(stderr, "Failed to dlopen() %s\n", pkcs11_lib_path);
		exit(EXIT_FAILURE);
	}

	dlclose(pkcs11_lib_handle);

	return EXIT_SUCCESS;
}

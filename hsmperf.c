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
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define OUT_OF_MEMORY_IF(cond) \
	if (cond) { \
		fprintf(stderr, "Out of memory at line %d\n", __LINE__); \
		exit(EXIT_FAILURE); \
	}

#define PKCS11_TIMED_CALL(function, start, stop, ...) \
	{ \
		CK_RV rv; \
		int i = 0; \
		while (strcmp(pkcs11_symbols[i].name, #function) != 0) \
			i++; \
		if (start) \
			clock_gettime(CLOCK_MONOTONIC, start); \
		rv = (*(CK_##function) pkcs11_symbols[i].ptr)(__VA_ARGS__); \
		if (stop) \
			clock_gettime(CLOCK_MONOTONIC, stop); \
		if (rv != CKR_OK) { \
			fprintf(stderr, "Error 0x%08x at line %d\n", \
				(unsigned int) rv, __LINE__); \
			exit(EXIT_FAILURE); \
		} \
	}

#define PKCS11_CALL(function, ...) \
	PKCS11_TIMED_CALL(function, NULL, NULL, __VA_ARGS__)

#define TIMESPEC_TO_NANOSECS(ts) (ts.tv_sec * 1000000000LL + ts.tv_nsec)

const char *usage_message =
	"Usage: hsmperf -l /path/to/libpkcs11.so"
	" [ -s slot ] [ -c iterations ] [ -v ]\n";

char *pkcs11_lib_path = NULL;
void *pkcs11_lib_handle = NULL;

struct {
	const char *name;
	void *ptr;
} pkcs11_symbols[] = {
	{ "C_CloseSession", NULL },
	{ "C_DigestFinal", NULL },
	{ "C_DigestInit", NULL },
	{ "C_DigestUpdate", NULL },
	{ "C_Finalize", NULL },
	{ "C_GetSlotList", NULL },
	{ "C_Initialize", NULL },
	{ "C_Login", NULL },
	{ "C_Logout", NULL },
	{ "C_OpenSession", NULL },
	{ NULL, NULL }
};

CK_SLOT_ID slot = 0;
unsigned int iterations = 1000;
unsigned short detail = 0;

void
resolve_pkcs11_symbols(void)
{
	int i = 0;
	const char *symbol;
	void *ptr;

	while (symbol = pkcs11_symbols[i].name) {
		ptr = dlsym(pkcs11_lib_handle, symbol);
		if (!ptr) {
			fprintf(stderr, "Failed to resolve %s\n", symbol);
			exit(EXIT_FAILURE);
		}
		pkcs11_symbols[i].ptr = ptr;
		i++;
	}
}

void
initialize()
{
	PKCS11_CALL(C_Initialize, NULL);
}

void
get_slot(CK_SLOT_ID *id)
{
	CK_ULONG count;
	CK_SLOT_ID *ids;

	PKCS11_CALL(C_GetSlotList, CK_TRUE, NULL, &count);
	if (*id > count - 1) {
		fprintf(stderr, "Slot %d not found\n", (int) *id);
		exit(EXIT_FAILURE);
	}

	ids = malloc(sizeof(CK_SLOT_ID) * count);
	OUT_OF_MEMORY_IF(!ids);
	PKCS11_CALL(C_GetSlotList, CK_TRUE, ids, &count);
	*id = ids[*id];
	free(ids);
}

void
start_session(CK_SESSION_HANDLE *session)
{
	PKCS11_CALL(C_OpenSession,
		    slot, CKF_SERIAL_SESSION, NULL, NULL, session);
}

void
login(CK_SESSION_HANDLE session, CK_BYTE *pin)
{
	PKCS11_CALL(C_Login,
		    session, CKU_USER, pin, strlen((char *) pin));
}

void
benchmark(CK_SESSION_HANDLE session, FILE *feed, CK_MECHANISM_TYPE type,
	  unsigned int digest_len, const char *mechanism_name)
{
	CK_MECHANISM mechanism;
	CK_ULONG digestlen = digest_len;
	unsigned char input[256];
	size_t input_read;
	unsigned char *digest;
	struct timespec ts[6];
	unsigned int *timings, timing;
	unsigned int tmin[4] = { UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX };
	unsigned int tmax[4] = { 0, 0, 0, 0 };
	unsigned long long ttotal[4] = {0, 0, 0, 0};
	unsigned int i, j;
	int pct, last_pct = -1;
	const char *phases[] = {
		"DigestInit",
		"DigestUpdate",
		"DigestFinal",
		"TOTAL"
	};

	mechanism.mechanism = type;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;

	digest = malloc(digest_len);
	OUT_OF_MEMORY_IF(!digest);
	timings = calloc(iterations, sizeof(int) * 4);
	OUT_OF_MEMORY_IF(!timings);
	for (i = 0; i < iterations; i++) {
		pct = 100 * i / iterations;
		if (pct > last_pct) {
			printf("\rTesting %s... %d%%", mechanism_name, pct);
			fflush(stdout);
			last_pct = pct;
		}
		input_read = fread(input, sizeof(input), 1, feed);
		if (input_read != 1) {
			fprintf(stderr, "Error getting random bytes\n");
			free(timings);
			return;
		}
		PKCS11_TIMED_CALL(C_DigestInit, &ts[0], &ts[1],
				  session, &mechanism);
		PKCS11_TIMED_CALL(C_DigestUpdate, &ts[2], &ts[3],
				  session, input, sizeof(input));
		PKCS11_TIMED_CALL(C_DigestFinal, &ts[4], &ts[5],
				  session, digest, &digestlen);
		for (j = 0; j < 6; j += 2) {
			timing = TIMESPEC_TO_NANOSECS(ts[j+1]);
			timing -= TIMESPEC_TO_NANOSECS(ts[j]);
			timings[i * 4 + j / 2] = timing;
			timings[i * 4 + 3] += timing;
		}
	}

	for (i = 0; i < iterations; i++) {
		for (j = 0; j < 4; j++) {
			timing = timings[i * 4 + j];
			if (timing < tmin[j])
				tmin[j] = timing;
			if (timing > tmax[j])
				tmax[j] = timing;
			ttotal[j] += timing;
		}
	}

	printf("\r");
	for (i = 3 - detail; i < 4; i++) {
		printf("%16s", mechanism_name);
		if (detail)
			printf(", %12s", phases[i]);
		printf(": ");
		printf("min %10.6f msec, max %10.6f msec, avg %10.6f msec\n",
		       (float) tmin[i] / 1000000, (float) tmax[i] / 1000000,
		       (float) ttotal[i] / iterations / 1000000);
	}
	if (detail)
		printf("\n");

	free(digest);
	free(timings);
}

void
logout(CK_SESSION_HANDLE session)
{
	PKCS11_CALL(C_Logout, session);
}

void
end_session(CK_SESSION_HANDLE session)
{
	PKCS11_CALL(C_CloseSession, session);
}

void
finalize()
{
	PKCS11_CALL(C_Finalize, NULL);
}

void
parse_options(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "l:s:c:v")) != -1) {
		switch (opt) {
		case 'l':
			pkcs11_lib_path = malloc(strlen(optarg) + 1);
			OUT_OF_MEMORY_IF(!pkcs11_lib_path);
			strcpy(pkcs11_lib_path, optarg);
			break;
		case 's':
			slot = (CK_SLOT_ID) atoi(optarg);
			break;
		case 'c':
			iterations = atoi(optarg);
			break;
		case 'v':
			detail = 3;
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
	CK_SESSION_HANDLE session;
	char *pin = NULL;
	FILE *urandom;

	parse_options(argc, argv);

	pkcs11_lib_handle = dlopen(pkcs11_lib_path, RTLD_LAZY);
	if (!pkcs11_lib_handle) {
		fprintf(stderr, "Failed to dlopen() %s\n", pkcs11_lib_path);
		exit(EXIT_FAILURE);
	}
	resolve_pkcs11_symbols();

	initialize();
	get_slot(&slot);
	start_session(&session);
	pin = getpass("Enter PIN: ");
	if (strlen(pin))
		login(session, (CK_BYTE *) pin);
	urandom = fopen("/dev/urandom", "r");
	if (!urandom) {
		perror("Failed to open /dev/urandom");
		exit(EXIT_FAILURE);
	}
	benchmark(session, urandom, CKM_SHA_1, 20, "SHA-1");
	benchmark(session, urandom, CKM_SHA256, 32, "SHA-256");
	benchmark(session, urandom, CKM_SHA512, 64, "SHA-512");
	fclose(urandom);
	if (strlen(pin))
		logout(session);
	end_session(session);
	finalize();

	dlclose(pkcs11_lib_handle);

	return EXIT_SUCCESS;
}

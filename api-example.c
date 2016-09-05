/*
 * Copyright 2011 Kano
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

/* Compile:
 *   /usr/bin/arm-angstrom-linux-gnueabi-gcc api-example.c -Icompat/jansson-2.6/src -Icompat/libusb-1.0/libusb -o cgminer-api
 *   cp /usr/bin/bmminer-api /usr/bin/cgminer-api
 *   cp /usr/bin/bmminer-api /usr/bin/bmminer-api-old
 *   chmod 777 /usr/bin/cgminer-api
 *   cp cgminer-api /usr/bin/bmminer-api
 *   chmod 777 /usr/bin/bmminer-api
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "compat.h"
#include "miner.h"

#if defined(unix) || defined(__APPLE__)
	#include <errno.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <netdb.h>

	#define SOCKETFAIL(a) ((a) < 0)
	#define INVSOCK -1
	#define CLOSESOCKET close

	#define SOCKETINIT {}

	#define SOCKERRMSG strerror(errno)
#endif



static const char SEPARATOR = '|';
static const char COMMA = ',';
static const char EQ = '=';
static int ONLY;

void display(char *buf)
{
	char *nextobj, *item, *nextitem, *eq;
	int itemcount;

	while (buf != NULL) {
		nextobj = strchr(buf, SEPARATOR);
		if (nextobj != NULL)
			*(nextobj++) = '\0';

		if (*buf) {
			item = buf;
			itemcount = 0;
			while (item != NULL) {
				nextitem = strchr(item, COMMA);
				if (nextitem != NULL)
					*(nextitem++) = '\0';

				if (*item) {
					eq = strchr(item, EQ);
					if (eq != NULL)
						*(eq++) = '\0';

					if (itemcount == 0)
						printf("[%s%s] =>\n(\n", item, (eq != NULL && isdigit(*eq)) ? eq : "");

					if (eq != NULL)
						printf("   [%s] => %s\n", item, eq);
					else
						printf("   [%d] => %s\n", itemcount, item);
				}

				item = nextitem;
				itemcount++;
			}
			if (itemcount > 0)
				puts(")");
		}

		buf = nextobj;
	}
}

#define SOCKSIZ 65535

int callapi(char *command, char *host, short int port)
{
	struct hostent *ip;
	struct sockaddr_in serv;
	SOCKETTYPE sock;
	int ret = 0;
	int n;
	char *buf = NULL;
	size_t len, p;

	SOCKETINIT;

	ip = gethostbyname(host);
	if (!ip) {
		printf("Couldn't get hostname: '%s'\n", host);
		return 1;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVSOCK) {
		printf("Socket initialisation failed: %s\n", SOCKERRMSG);
		return 1;
	}

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr = *((struct in_addr *)ip->h_addr);
	serv.sin_port = htons(port);

	if (SOCKETFAIL(connect(sock, (struct sockaddr *)&serv, sizeof(struct sockaddr)))) {
		printf("Socket connect failed: %s\n", SOCKERRMSG);
		return 1;
	}

	n = send(sock, command, strlen(command), 0);
	if (SOCKETFAIL(n)) {
		printf("Send failed: %s\n", SOCKERRMSG);
		ret = 1;
	}
	else {
		len = SOCKSIZ;
		buf = malloc(len+1);
		if (!buf) {
			printf("Err: OOM (%d)\n", (int)(len+1));
			return 1;
		}
		p = 0;
		while (42) {
			if ((len - p) < 1) {
				len += SOCKSIZ;
				buf = realloc(buf, len+1);
				if (!buf) {
					printf("Err: OOM (%d)\n", (int)(len+1));
					return 1;
				}
			}

			n = recv(sock, &buf[p], len - p , 0);

			if (SOCKETFAIL(n)) {
				printf("Recv failed: %s\n", SOCKERRMSG);
				ret = 1;
				break;
			}

			if (n == 0)
				break;

			p += n;
		}
		buf[p] = '\0';

		if (ONLY)
			printf("%s\n", buf);
		else {
			printf("Reply was '%s'\n", buf);
			display(buf);
		}
	}

	CLOSESOCKET(sock);

	return ret;
}

static char *trim(char *str)
{
	char *ptr;

	while (isspace(*str))
		str++;

	ptr = strchr(str, '\0');
	while (ptr-- > str) {
		if (isspace(*ptr))
			*ptr = '\0';
	}

	return str;
}

int main(int argc, char *argv[])
{
	char *command = "summary";
	char *host = "127.0.0.1";
	short int port = 4028;
	char *ptr;
	int i = 1;

	if (argc > 1)
		if (strcmp(argv[1], "-?") == 0
		||  strcmp(argv[1], "-h") == 0
		||  strcmp(argv[1], "--help") == 0) {
			fprintf(stderr, "usAge: %s [command [ip/host [port]]]\n", argv[0]);
			return 1;
		}

	if (argc > 1)
		if (strcmp(argv[1], "-o") == 0) {
			ONLY = 1;
			i = 2;
		}

	if (argc > i) {
		ptr = trim(argv[i++]);
		if (strlen(ptr) > 0)
			command = ptr;
	}

	if (argc > i) {
		ptr = trim(argv[i++]);
		if (strlen(ptr) > 0)
			host = ptr;
	}

	if (argc > i) {
		ptr = trim(argv[i]);
		if (strlen(ptr) > 0)
			port = atoi(ptr);
	}

	return callapi(command, host, port);
}

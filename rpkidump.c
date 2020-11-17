/*	$Id: test-mft.c,v 1.8 2020/11/03 21:16:32 tb Exp $ */
/*
 * Copyright (c) 2020 Job Snijders <job@openbsd.org>
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "extern.h"
#include "rpkidump.h"

int
main(int argc, char *argv[])
{
	char		*ft;
	int		 ch;
	struct mft	*p;
	BIO		*bio_out = NULL;
	X509		*xp = NULL;

	if (pledge("stdio rpath", NULL) == -1)
		err(1, "pledge");

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	ERR_load_crypto_strings();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

	if ((bio_out = BIO_new_fp(stdout, BIO_NOCLOSE)) == NULL)
		errx(1, "BIO_new_fp");

	if ((ft = strrchr(argv[0], '.')) == NULL)
		errx(1, "unknown filetype");

	/* manifest */
	if (strcmp(ft, ".mft") == 0) {
		if ((p = mft_parse(&xp, argv[0])) == NULL) {
			mft_print(p);
			if (!PEM_write_bio_X509(bio_out, xp))
				errx(1, "PEM_write_bio_X509: unable to write cert");
			mft_free(p);
			X509_free(xp);
		}
	} else {
		errx(1, "geen idee");
	}

	BIO_free(bio_out);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();

	return 0;
}

extern char *__progname;

static void __dead
usage(void)
{
	(void)fprintf(stderr, "usage: %s filename\n", __progname);
	exit(1);
}

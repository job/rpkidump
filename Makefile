#	$OpenBSD: Makefile,v 1.10 2019/05/08 21:30:11 benno Exp $

.PATH:	${.CURDIR}/../../usr.sbin/rpki-client

PROG=	rpkidump
SRCS=	rpkidump.c print.c \
	as.c cert.c cms.c io.c ip.c log.c mft.c roa.c x509.c

LDADD+= -lcrypto -lm
DPADD+= ${LIBCRYPTO} ${LIBM}

CFLAGS+=        -I${.CURDIR} -I${.CURDIR}/../../usr.sbin/rpki-client

CFLAGS+=-g -W -Wall -Wextra

.include <bsd.prog.mk>

/* rxgk/rxgk_util.c - utility functions for RXGK use */
/*
 * Copyright (C) 2013, 2014 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * Utility functions for RXGK use. Compute the security overhead for a
 * connection at a given security level, and helpers for maintaining key
 * version numbers for connections.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <afs/opr.h>
#include <rx/rx.h>
#include <rx/rx_identity.h>
#include <rx/rxgk.h>
#include <rx/rx_packet.h>
#include <afs/rfc3961.h>
#ifdef KERNEL
# include "afs/sysincludes.h"
# include "afsincludes.h"
#else
# include <errno.h>
#endif

#include "rxgk_private.h"

/**
 * Set the security header and trailer sizes on a connection
 *
 * Set the security header and trailer sizes on aconn to be consistent
 * with the space needed for packet handling at the given security level
 * using the given key (only its enctype/checksum type are relevant).
 *
 * @param[out] aconn	The connection being modified.
 * @param[in] level	The security level of the connection.
 * @param[in] k0	The master key for the connection.
 * @return rxgk error codes.
 */
afs_int32
rxgk_security_overhead(struct rx_connection *aconn, RXGK_Level level,
		       rxgk_key k0)
{
    afs_int32 ret;
    size_t mlen;
    afs_uint32 elen;

    switch (level) {
	case RXGK_LEVEL_CLEAR:
	    return 0;
	case RXGK_LEVEL_AUTH:
	    ret = rxgk_mic_length(k0, &mlen);
	    if (ret != 0)
		return ret;
	    rx_SetSecurityHeaderSize(aconn, mlen);
	    rx_SetSecurityMaxTrailerSize(aconn, 0);
	    return 0;
	case RXGK_LEVEL_CRYPT:
	    ret = rxgk_cipher_expansion(k0, &elen);
	    if (ret != 0)
		return ret;
	    rx_SetSecurityHeaderSize(aconn, sizeof(struct rxgk_header));
	    rx_SetSecurityMaxTrailerSize(aconn, elen);
	    return 0;
	default:
	    return RXGK_INCONSISTENCY;
    }
}

/**
 * Compute the full 32-bit kvno of a connection
 *
 * Given the 16-bit wire kvno and the local state, return the actual kvno which
 * should be used for key derivation. All values are in host byte order.
 * Understanding how we derive a 32-bit kvno from a 16-bit value requires some
 * explanation:
 *
 * After an rxgk conn is set up, our peer informs us of kvno changes by sending
 * the lowest 16 bits of its kvno. The real kvno being used is a 32-bit value,
 * but the peer cannot change the kvno arbitrarily; the protocol spec only
 * allows a peer to change the kvno by incrementing or decrementing it by 1. So
 * if we know the current 32-bit kvno ('local'), and we know the advertised
 * lower 16 bits of the new kvno ('wire'), we can calculate the new 32-bit kvno
 * ('*real').
 *
 * @param[in] wire	The 16-bit kvno from the received packet.
 * @param[in] local	The 32-bit kvno from the local connection state.
 * @param[out] real	The kvno to be used to process this packet.
 * @return rxgk error codes.
 */
afs_int32
rxgk_key_number(afs_uint16 wire, afs_uint32 local, afs_uint32 *real)
{
    afs_uint16 lres, diff;

    lres = local % (1u << 16);
    diff = (afs_uint16)(wire - lres);

    if (diff == 0) {
	*real = local;
    } else if (diff == 1) {
	/* Our peer is using a kvno 1 higher than 'local' */
	if (local == MAX_AFS_UINT32)
	    return RXGK_INCONSISTENCY;
	*real = local + 1;

    } else if (diff == (afs_uint16)0xffffu) {
	/* Our peer is using a kvno 1 lower than 'local' */
	if (local == 0)
	    return RXGK_INCONSISTENCY;
	*real = local - 1;

    } else {
	return RXGK_BADKEYNO;
    }
    return 0;
}

/**
 * Choose an rxgk level out of a list
 *
 * Given a list of rxgk levels (ordered by preference), pick the first one
 * that we understand and is allowed, and return it in 'a_level'. If we
 * cannot find one, return RXGK_BADLEVEL.
 *
 * @param[in] levels	An array of levels, 'n_levels' long
 * @param[in] n_levels	The length of 'levels'
 * @param[out] a_level	The chosen level
 *
 * @return rxgk error codes
 */
afs_int32
rxgk_choose_level(RXGK_Level *levels, int n_levels, RXGK_Level *a_level)
{
    int level_i;
    for (level_i = 0; level_i < n_levels; level_i++) {
	/* For now, only allow CRYPT. In the future, we should have runtime
	 * options for different policies. */
	if (levels[level_i] == RXGK_LEVEL_CRYPT) {
	    *a_level = levels[level_i];
	    return 0;
	}
    }

    /* We couldn't find a valid level (or the list was empty). */
    return RXGK_BADLEVEL;
}

#ifndef KERNEL
/*
 * This tries to follow the same algorithm as the 524 logic in
 * tkt_DecodeTicket5, which itself was copied from MIT's
 * krb5_524_conv_principal. The code is different, though, since we do the
 * conversion in-place on a plain string, instead of a parsed krb5 princ
 * structure.
 */
static int
conv_princ_524(char *princ, int disableDotCheck)
{
    struct krb_convert {
	char *v4_str;
	char *v5_str;
	unsigned int flags;
	unsigned int len;
    };

# define DO_REALM_CONVERSION 0x00000001

    /* Realm conversion, Change service name */
# define RC(V5NAME,V4NAME) { V5NAME, V4NAME, DO_REALM_CONVERSION, sizeof(V5NAME)-1 }
    /* Realm conversion */
# define R(NAME)         { NAME, NAME, DO_REALM_CONVERSION, sizeof(NAME)-1 }
    /* No Realm conversion */
# define NR(NAME)        { NAME, NAME, 0, sizeof(NAME)-1 }
    static const struct krb_convert sconv_list[] = {
	NR("kadmin"),
	RC("rcmd", "host"),
	R("discuss"),
	R("rvdsrv"),
	R("sample"),
	R("olc"),
	R("pop"),
	R("sis"),
	R("rfs"),
	R("imap"),
	R("ftp"),
	R("ecat"),
	R("daemon"),
	R("gnats"),
	R("moira"),
	R("prms"),
	R("mandarin"),
	R("register"),
	R("changepw"),
	R("sms"),
	R("afpserver"),
	R("gdss"),
	R("news"),
	R("abs"),
	R("nfs"),
	R("tftp"),
	NR("zephyr"),
	R("http"),
	R("khttp"),
	R("pgpsigner"),
	R("irc"),
	R("mandarin-agent"),
	R("write"),
	R("palladium"),
	R("imap"),
	R("smtp"),
	R("lmtp"),
	R("ldap"),
	R("acap"),
	R("argus"),
	R("mupdate"),
	R("argus"),
	{0, 0, 0, 0},
    };
# undef R
# undef RC
# undef NR

    const struct krb_convert *conv;
    char *atsign;
    char *realm;
    char *name;
    size_t name_len;
    char *sep;
    char *inst = NULL;
    char *end;

    /* Find the realm, and separate it from the princ name. */
    atsign = strchr(princ, '@');
    if (atsign == NULL) {
	/* No realm? */
	return RXGK_BAD_TOKEN;
    }

    *atsign = '\0';
    realm = &atsign[1];
    if (realm[0] == '\0') {
	/* Empty realm? */
	goto bad;
    }

    if (strchr(realm, '@') != NULL) {
	/* Realm contains an '@'? That's not right... */
	goto bad;
    }

    /*
     * Find the (first) instance separator, and if found, separate the first
     * two name components.
     */
    name = princ;
    sep = strchr(name, '/');
    if (sep != NULL) {
	*sep = '\0';
	inst = &sep[1];
    }

    if (!disableDotCheck && strchr(name, '.') != NULL) {
	/* There's a '.' in the first component of the princ name. */
	goto bad;
    }

    if (name[0] == '\0') {
	/* Empty name? */
	goto bad;
    }

    if (inst == NULL) {
	/*
	 * If we just have one name component, we can use it as-is. Restore the
	 * '@' realm separator and return.
	 */
	*atsign = '@';
	return 0;
    }

    if (strchr(inst, '/') != NULL) {
	/* We have more than 2 components in 'name'. */
	goto bad;
    }

    if (inst[0] == '\0') {
	/* Empty instance? */
	goto bad;
    }

    /*
     * We have exactly 2 components in our name: the name, and the
     * instance. Go through the historical list of 5-to-4 princ name
     * translations.
     */
    name_len = strlen(name);
    for (conv = sconv_list; conv->v4_str; conv++) {
	if (conv->len != name_len) {
	    continue;
	}
	if (strcmp(conv->v5_str, name) != 0) {
	    continue;
	}
	/* e.g. translate "host" -> "rcmd" */
	memcpy(name, conv->v4_str, name_len);
	if ((conv->flags & DO_REALM_CONVERSION)) {
	    /*
	     * e.g. For imap/foo.example.com, trim off the trailing
	     * ".example.com"
	     */
	    char *dot = strchr(inst, '.');
	    if (dot == NULL) {
		goto bad;
	    }
	    *dot = '\0';
	} else {
	    inst = NULL;
	}
	break;
    }

    if (inst != NULL) {
	/* Restore our '/' separator, but set it to the krb4-style '.' now. */
	*sep = '.';
    }

    /*
     * 'princ' now consists of "name.inst\0[...]realm" where the [...] might be
     * nothing. Transform this into name.inst@realm by appending an '@', and
     * moving the realm to right after the '@'.
     */
    end = &princ[strlen(princ)];
    *end = '@';
    end++;
    if (end != realm) {
	memmove(end, realm, strlen(realm)+1);
    }

    return 0;

 bad:
    return RXGK_BAD_TOKEN;
}

# define PRINC_HEADER ("\x04\x01\x00\x0b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02")
struct princ_data {
    char header[sizeof(PRINC_HEADER)-1];
    afs_uint32 princ_length_n;
    char princ[];
} __attribute__((packed));
# define PRINC_DATA_SIZE (19)

static afs_int32
extract_krb5_princ(struct rx_opaque *name, char **a_princ)
{
    /*
     * An exported name with a krb5 princ will start with this sequence of
     * bytes. This contains the krb5 mech OID, and some lengths and stuff.
     */
    static const char *princ_header = PRINC_HEADER;
    static const size_t princ_header_len = sizeof(PRINC_HEADER)-1;

    char *princ;
    struct princ_data *data = name->val;
    size_t len = name->len;
    afs_uint32 princ_len;

    opr_StaticAssert(sizeof(*data) == PRINC_DATA_SIZE);

    if (len < sizeof(*data)) {
	return RXGK_BAD_TOKEN;
    }
    len -= sizeof(*data);

    /* Check the header. */
    if (memcmp(data->header, princ_header, princ_header_len) != 0) {
	return RXGK_BAD_TOKEN;
    }

    /* Get our length; 4 bytes, in NBO. */
    memcpy(&princ_len, &data->princ_length_n, sizeof(data->princ_length_n));
    princ_len = ntohl(princ_len);

    if (princ_len >= 256) {
	/*
	 * Arbitrarily cap the length of the princ name we'll accept, just to
	 * make sure we don't accidentally try to read a big chunk of data.
	 */
	return RXGK_BAD_TOKEN;
    }

    if (princ_len > len) {
	/* The data said we had 'princ_len' bytes for the principal string, but
	 * we only have 'len' bytes left in the buffer. */
	return RXGK_BAD_TOKEN;
    }

    if (princ_len < 1) {
	/* Our princ string is empty? */
	return RXGK_BAD_TOKEN;
    }

    /* +1 for the trailing NUL byte */
    princ = calloc(princ_len+1, 1);
    if (princ == NULL) {
	return RXGK_INCONSISTENCY;
    }
    memcpy(princ, data->princ, princ_len);

    *a_princ = princ;
    return 0;
}

/**
 * Convert a krb5-backed GSS identity into a krb4 identity.
 *
 * @param[in] gss_id	The GSS identity to convert.
 * @param[in] flags	Flags. If RXGK_524CONV_DISABLE_DOTCHECK is not given,
 *			we'll refuse to convert principals whose first name
 *			component contains a dot ('.')
 * @param[out] a_k4id	On success, set to the converted krb4 identity.
 * @return rxgk error codes
 */
afs_int32
rxgk_524_conv_id(struct rx_identity *gss_id, afs_uint32 flags,
		 struct rx_identity **a_k4id)
{
    char *princ = NULL;
    afs_int32 code;
    int disableDotCheck = 0;

    if ((flags & RXGK_524CONV_DISABLE_DOTCHECK)) {
	disableDotCheck = 1;
    }

    if (gss_id->kind != RX_ID_GSS) {
	code = RXGK_INCONSISTENCY;
	goto done;
    }

    code = extract_krb5_princ(&gss_id->exportedName, &princ);
    if (code != 0) {
	goto done;
    }

    code = conv_princ_524(princ, disableDotCheck);
    if (code != 0) {
	goto done;
    }

    *a_k4id = rx_identity_new(RX_ID_KRB4, princ, princ, strlen(princ)+1);
    if (*a_k4id == NULL) {
	code = RXGK_INCONSISTENCY;
	goto done;
    }

 done:
    free(princ);
    return code;
}

/**
 * Convert a krb5 principal into a GSS exported name.
 *
 * @param[in] krb5_princ    The krb5 principal string.
 * @param[out] gss_data	    The exported data for a GSS identity for the given
 *			    krb5 principal.
 * @returns rxgk error codes
 */
afs_int32
rxgk_krb5_to_gss(char *krb5_princ, struct rx_opaque *gss_data)
{
    static const char *princ_header = PRINC_HEADER;
    static const size_t princ_header_len = sizeof(PRINC_HEADER)-1;

    struct princ_data *data;
    afs_uint32 princ_len;
    size_t data_len;
    afs_int32 code;

    opr_StaticAssert(sizeof(*data) == PRINC_DATA_SIZE);

    princ_len = strlen(krb5_princ);
    data_len = princ_len + sizeof(*data);

    data = calloc(data_len, 1);
    if (data == NULL) {
	return RXGK_INCONSISTENCY;
    }

    memcpy(data->header, princ_header, princ_header_len);
    data->princ_length_n = htonl(princ_len);
    memcpy(data->princ, krb5_princ, princ_len);

    code = rx_opaque_populate(gss_data, data, data_len);
    free(data);

    if (code != 0) {
	return RXGK_INCONSISTENCY;
    }
    return 0;
}
#endif /* !KERNEL */

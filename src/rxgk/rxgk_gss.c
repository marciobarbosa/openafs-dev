/* rxgk/rxgk_gss.c - RXGK routines that interface with the GSS-API */
/*
 * Copyright (C) 2013 by the Massachusetts Institute of Technology.
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
 * RXGK routines that involve GSS types or make calls into the GSS-API
 * library.
 * These routines must be separated out into their own object file
 * because there are rxgk consumers (such as the kernel cache manager)
 * which do not have a GSS-API library available.
 *
 * In particular, this file contains the core routines for performing
 * the client side of the GSS negotiation loop -- what the client uses to get a
 * token. This also contains a number of helper routines which, though they do
 * not directly interact with GSSAPI types, are best placed as file-local
 * helpers for the core routines in question.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#ifdef AFS_RXGK_GSS_ENV

#include <afs/afsutil.h>

#include <rx/rx.h>
#include <rx/rxgk.h>
#include <gssapi/gssapi.h>
#ifdef HAVE_GSSAPI_GSSAPI_KRB5_H
# include <gssapi/gssapi_krb5.h>
#endif
#include <errno.h>

#include "rxgk_private.h"

/* FreeBSD has a broken gssapi.h, and maybe others. */
#ifndef GSS_C_PRF_KEY_FULL
# define GSS_C_PRF_KEY_FULL 0
#endif

/* The client_nonce/server_nonce values we generate are at least this long. */
#define MIN_NONCE_LEN 20

/*
 * A central place for processing misc unexpected errors, just so we log when
 * they occur, and we can easily change what error code we use.
 */
static_inline afs_int32
_misc_error_line(const char *fname, int line)
{
    ViceLog_limit(0, ("rxgk: Internal error at %s:%d. Please report a bug if "
		      "this causes problems.\n", fname, line));
    return RXGK_INCONSISTENCY;
}
#define misc_error() _misc_error_line(__FILE__, __LINE__)

/* Don't call this directly; call log_gss_error instead */
static void
_log_gss_code(const char *prefix, afs_uint32 status, int is_major)
{
    afs_uint32 msg_ctx = 0;
    gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
    int status_type = is_major ? GSS_C_GSS_CODE : GSS_C_MECH_CODE;
    do {
	afs_uint32 major, minor;
	major = gss_display_status(&minor, status, status_type,
				   (gss_OID)gss_mech_krb5, &msg_ctx, &msg);
	if (major != GSS_S_COMPLETE) {
	    ViceLog(0, ("%s: Error displaying error: gss_display_status(%u, %d) "
			"= %u, %u\n",
			prefix, status, status_type, major, minor));
	    return;
	}
	ViceLog(0, ("%s: %.*s [%u]\n", prefix, (int)msg.length,
		    (char*)msg.value, status));
	gss_release_buffer(&minor, &msg);
    } while (msg_ctx != 0);
}

static void
log_gss_error(const char *prefix, afs_uint32 major, afs_uint32 minor)
{
    _log_gss_code(prefix, major, 1);
    if (minor != 0) {
	_log_gss_code(prefix, minor, 0);
    }
}

/* Translate GSS major/minor status codes into rxgk error codes. */
static_inline afs_int32
gss2rxgk_error(const char *prefix, afs_uint32 major, afs_uint32 minor)
{
    if (!GSS_ERROR(major)) {
	return 0;
    }

    /* Some errors from GSS have well-defined meanings that map to our RXGK_
     * error codes. */
    switch (GSS_ROUTINE_ERROR(major)) {
    case GSS_S_DEFECTIVE_TOKEN:
    case GSS_S_BAD_SIG:
	return RXGK_SEALED_INCON;

    case GSS_S_DEFECTIVE_CREDENTIAL:
	return RXGK_BAD_TOKEN;

    case GSS_S_CREDENTIALS_EXPIRED:
	return RXGK_EXPIRED;
    }

    /* For others, return RXGK_INCONSISTENCY, but log more details. */
    log_gss_error(prefix, major, minor);

    return RXGK_INCONSISTENCY;
}

/**
 * Helper to make a token master key from a GSS security context
 *
 * Generate a token master key from a complete GSS security context and
 * some other data.  Used by both client and server.
 *
 * @param[in] gss_ctx		The (complete) GSS security context used to
 *				generate the token master key.
 * @param[in] client_nonce	The nonce supplied by the client.
 * @param[in] server_nonce	The nonce supplied by the server.
 * @param[in] enctype		The enctype that is used to generate k0.
 * @param[out] key		The generated token master key.
 *
 * @return rx error codes, errno codes
 */
static afs_uint32
rxgk_make_k0(gss_ctx_id_t gss_ctx, RXGK_Data *client_nonce,
	     RXGK_Data *server_nonce, afs_int32 enctype, gss_buffer_t key)
{
    gss_buffer_desc seed;
    ssize_t elen;
    char *buf;
    afs_uint32 major, minor = 0;

    elen = rxgk_etype_to_len(enctype);
    if (elen == -1)
	return RXGK_BADETYPE;

    seed.length = client_nonce->len + server_nonce->len;
    seed.value = rxi_Alloc(seed.length);
    if (seed.value == NULL) {
	return misc_error();
    }

    buf = seed.value;
    memcpy(buf, client_nonce->val, client_nonce->len);
    buf += client_nonce->len;
    memcpy(buf, server_nonce->val, server_nonce->len);

    major = gss_pseudo_random(&minor, gss_ctx, GSS_C_PRF_KEY_FULL,
			      &seed, elen, key);
    memset(seed.value, 0, seed.length);
    rxi_Free(seed.value, seed.length);

    return gss2rxgk_error("gss_pseudo_random", major, minor);
}

/*
 * Populate a StartParams structure.
 * Just use fixed values for now.
 *
 * Returns RX error codes, or errno codes.
 */
static afs_int32
fill_start_params(RXGK_StartParams *params, RXGK_Level level)
{
    size_t len;
    afs_int32 code;

    memset(params, 0, sizeof(*params));

    code = rxgk_default_enctypes(&params->enctypes);
    if (code != 0) {
	goto error;
    }

    /* security levels */
    len = 1;
    params->levels.val = xdr_alloc(len * sizeof(params->levels.val[0]));
    if (params->levels.val == NULL) {
	code = misc_error();
	goto error;
    }
    params->levels.len = len;
    params->levels.val[0] = level;

    /* lifetimes (advisory) */
    params->lifetime = 60 * 60 * 10;	/* 10 hours */
    params->bytelife = 30;		/* 1 GiB */

    /* Use a random nonce; 20 bytes is UUID-length. */
    code = rxgk_nonce(&params->client_nonce, MIN_NONCE_LEN);
    if (code != 0) {
	goto error;
    }
    return 0;

 error:
    xdrfree_RXGK_StartParams(params);
    memset(params, 0, sizeof(*params));
    return code;
}

/*
 * Import the (GSS) name of the remote server to contact.
 *
 * Returns Rx error codes, or errno codes.
 */
static afs_int32
import_name(char *target, gss_name_t *target_name)
{
    gss_buffer_desc name_tmp;
    afs_uint32 major, minor = 0;

    name_tmp.length = strlen(target);
    name_tmp.value = target;
    major = gss_import_name(&minor, &name_tmp,
			    GSS_C_NT_HOSTBASED_SERVICE,
			    target_name);
    return gss2rxgk_error("gss_import_name", major, minor);
}

/*
 * Decrypt the encrypted reply from the server containing the ClientInfo
 * structure using gss_unwrap, and decode the XDR representation into an
 * actual ClientInfo structure.
 *
 * Returns Rx error codes, or errno codes.
 */
static afs_int32
decode_clientinfo(gss_ctx_id_t gss_ctx, RXGK_Data *info_in,
		  RXGK_ClientInfo *info_out)
{
    XDR xdrs;
    gss_buffer_desc enc_buf, clear_buf;
    gss_qop_t qop_state;
    afs_uint32 dummy;
    afs_uint32 major, minor = 0;
    int conf_state;
    afs_int32 code;

    memset(&xdrs, 0, sizeof(xdrs));
    memset(&clear_buf, 0, sizeof(clear_buf));

    enc_buf.length = info_in->len;
    enc_buf.value = info_in->val;
    major = gss_unwrap(&minor, gss_ctx, &enc_buf, &clear_buf,
		       &conf_state, &qop_state);
    code = gss2rxgk_error("gss_unwrap", major, minor);
    if (code != 0) {
	goto done;
    }
    if (conf_state == 0 || qop_state != GSS_C_QOP_DEFAULT) {
	code = RXGK_BAD_QOP;
	goto done;
    }

    xdrmem_create(&xdrs, clear_buf.value, clear_buf.length,
		  XDR_DECODE);
    if (!xdr_RXGK_ClientInfo(&xdrs, info_out)) {
	code = RXGK_SEALED_INCON;
	goto done;
    }

 done:
    (void)gss_release_buffer(&dummy, &clear_buf);
    if (xdrs.x_ops)
	xdr_destroy(&xdrs);
    return code;
}

/*
 * XDR-encode an RXGK_StartParams into 'buf'. Memory in 'buf' is allocated via
 * rxi_Alloc and must be freed by the caller (on success, and on error).
 */
static afs_int32
encode_startparams(RXGK_StartParams *client_start, gss_buffer_desc *buf)
{
    XDR xdrs;
    afs_int32 code;
    afs_uint32 len;

    xdrlen_create(&xdrs);
    if (!xdr_RXGK_StartParams(&xdrs, client_start)) {
	code = misc_error();
	goto done;
    }
    len = xdr_getpos(&xdrs);
    xdr_destroy(&xdrs);
    memset(&xdrs, 0, sizeof(xdrs));

    buf->value = rxi_Alloc(len);
    if (buf->value == NULL) {
	code = misc_error();
	goto done;
    }
    buf->length = len;

    xdrmem_create(&xdrs, buf->value, len, XDR_ENCODE);
    if (!xdr_RXGK_StartParams(&xdrs, client_start)) {
	code = misc_error();
	goto done;
    }

    /* double-check that we actually encoded 'buf->length' bytes */
    len = xdr_getpos(&xdrs);
    if (len != buf->length) {
	code = misc_error();
	goto done;
    }

    code = 0;

 done:
    if (xdrs.x_ops) {
	xdr_destroy(&xdrs);
    }
    return code;
}

static afs_int32
check_clientinfo(gss_ctx_id_t gss_ctx, RXGK_ClientInfo *clientinfo,
		 RXGK_StartParams *params)
{
    gss_buffer_desc startparams_buf;
    gss_buffer_desc mic_buf;
    gss_qop_t qop_state;
    afs_uint32 major, minor;

    afs_int32 code;
    int item_i;
    int found;

    memset(&startparams_buf, 0, sizeof(startparams_buf));

    /* First, check if the server gave us an explicit error code. */
    code = clientinfo->errorcode;
    if (code != 0) {
	if (code < 0) {
	    /*
	     * Don't let the server set a negative error code; those are
	     * reserved for network errors while trying to contact the server
	     * to run GSSNegotiate at all.
	     */
	    ViceLog(0, ("rxgk: error: GSS server provided invalid error code "
			"%d.\n", code));
	    goto sealed_incon;
	}
	goto done;
    }

    /* Next, check if the given mic matches the startparams that we sent for
     * the request. */

    code = encode_startparams(params, &startparams_buf);
    if (code != 0) {
	goto done;
    }

    mic_buf.value = clientinfo->mic.val;
    mic_buf.length = clientinfo->mic.len;

    major = gss_verify_mic(&minor, gss_ctx, &startparams_buf, &mic_buf,
			   &qop_state);
    code = gss2rxgk_error("gss_verify_mic", major, minor);
    if (code != 0) {
	goto done;
    }
    if (qop_state != GSS_C_QOP_DEFAULT) {
	code = RXGK_BAD_QOP;
	goto done;
    }

    /* Is the provided enctype one of the enctypes we requested? */
    for (found = 0, item_i = 0; item_i < params->enctypes.len; item_i++) {
	if (clientinfo->enctype == params->enctypes.val[item_i]) {
	    found = 1;
	    break;
	}
    }
    if (!found) {
	ViceLog(0, ("rxgk: error: GSS server provided not-requested enctype %d.\n",
		    clientinfo->enctype));
	goto sealed_incon;
    }

    /* Is the provided level one of the levels we requested? */
    for (found = 0, item_i = 0; item_i < params->levels.len; item_i++) {
	if (clientinfo->level == params->levels.val[item_i]) {
	    found = 1;
	    break;
	}
    }
    if (!found) {
	ViceLog(0, ("rxgk: error: GSS server provided not-requested security "
		    "level %d.\n", clientinfo->level));
	goto sealed_incon;
    }

    /* Check if we got an invalid negative expiration time. */
    if (clientinfo->expiration < 0) {
	ViceLog(0, ("rxgk: error: GSS server provided invalid expiration time "
		    "%ld.\n", (long)clientinfo->expiration));
	goto sealed_incon;
    }

    /* Check if the server gave us an empty token or nonce. */
    if (clientinfo->token.len < 1 || clientinfo->server_nonce.len < 1) {
	ViceLog(0, ("rxgk: error: GSS server provided empty token/nonce (token "
		    "%ld, nonce %ld)\n",
		    (long)clientinfo->token.len,
		    (long)clientinfo->server_nonce.len));
	goto sealed_incon;
    }

 done:
    rxi_Free(startparams_buf.value, startparams_buf.length);
    return code;

 sealed_incon:
    code = RXGK_SEALED_INCON;
    goto done;
}

struct rxgk_gss_isc_state {
    int pass;

    afs_uint32 major;

    /* The GSS token we receive from the server, and give to
     * gss_init_sec_context. */
    RXGK_Data rxgk_recv_token;

    /* The GSS token we get from gss_init_sec_context, and send to the server. */
    gss_buffer_desc gss_send_token;
};

/**
 * Run the gss_init_sec_context portions of our GSS negotiation.
 *
 * After this returns successfully, if GSS_S_CONTINUE_NEEDED is set in
 * isc->major, the caller should call this function again.
 *
 * After this returns successfully, if isc->gss_send_token is non-empty, the
 * caller should call RXGK_GSSNegotiate to send isc->gss_send_token to the
 * server, and receive a new token back. The caller should do this before
 * calling this function again (if isc->major says to do so, as mentioned
 * above).
 *
 * Note that both of the above conditions usually occur on the first pass, but
 * on subsequent passes either can happen somewhat independently of each other;
 * they are separate checks.
 *
 * Currently we don't support sending data to the server more than once; we'll
 * throw an error if gss_init_sec_context tells us to do so.
 *
 * @param[in,out] isc	    Our gss_init_sec_context state.
 * @param[in,out] gss_ctx   The GSS security context.
 * @param[in] target_name   The name of the GSS target (e.g. the krb5
 *			    service princ afs-rxgk/_afs.cell@REALM)
 * @return rx error codes, errno codes.
 */
static afs_int32
negoclient_isc(struct rxgk_gss_isc_state *isc, gss_ctx_id_t *gss_ctx,
	       gss_name_t target_name)
{
    afs_uint32 flags_in;
    afs_uint32 flags_out = 0;
    afs_uint32 major, minor = 0;
    afs_int32 code;

    gss_buffer_desc gss_recv_token;

    isc->pass++;
    if (isc->pass > 100) {
	/* If we've ran gss_init_sec_context over 100 times, something is
	 * clearly wrong. */
	code = misc_error();
	goto done;
    }

    flags_in = GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;

    gss_recv_token.value = isc->rxgk_recv_token.val;
    gss_recv_token.length = isc->rxgk_recv_token.len;

    if (isc->gss_send_token.value) {
	/*
	 * We're allocating a new gss_send_token now. Make sure there isn't
	 * already a buffer allocated for it; since any buffer from a previous
	 * pass should have already been freed.
	 */
	code = misc_error();
	goto done;
    }

    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, gss_ctx,
				 target_name, GSS_C_NO_OID, flags_in,
				 0 /* time */, GSS_C_NO_CHANNEL_BINDINGS,
				 &gss_recv_token,
				 NULL /* actual mech type */,
				 &isc->gss_send_token, &flags_out,
				 NULL /* time_rec */);
    code = gss2rxgk_error("gss_init_sec_context", major, minor);
    if (code != 0) {
	goto done;
    }
    if (isc->pass > 1 && isc->gss_send_token.length > 0) {
	/*
	 * This is not our first pass, and gss_init_sec_context says we need to
	 * send some more data to the server. We don't support multiple round
	 * trips yet, so bail out.
	 */
	ViceLog(0, ("rxgk: gss_init_sec_context requires multiple round trips, "
		    "which we do not yet support; bailing out. (pass %d, "
		    "send_token.length %u)\n",
		    isc->pass, (unsigned)isc->gss_send_token.length));
	code = EPROTONOSUPPORT;
	goto done;
    }

    if (major == GSS_S_COMPLETE && (flags_out & flags_in) != flags_in) {
	/*
	 * Our security context is complete. Check if all of our requested
	 * flags are actually supported. If some of them aren't, flags_out
	 * will be missing some of the requested flags.
	 */
	ViceLog(0, ("rxgk: error: gss_init_sec_context indicated missing "
		    "flags. (flags_in 0x%x, flags_out 0x%x)\n",
		    flags_in, flags_out));
	code = RXGK_BAD_QOP;
	goto done;
    }

    isc->major = major;

 done:
    xdrfree_RXGK_Data(&isc->rxgk_recv_token);
    memset(&isc->rxgk_recv_token, 0, sizeof(isc->rxgk_recv_token));

    return code;
}

/*
 * Send our local GSS token to the server, via RXGK_GSSNegotiate, and possibly
 * get a new GSS token back and an RXGK token.
 *
 * @param[in,out] isc	Our gss_init_sec_context state.
 * @param[in] conn	The rx connection over which the GSSNegotiate RPC
 *			is called.
 * @param[in] params	The RXGK_StartParams used for the GSSNegotiate RPC.
 * @param[out] clientinfo_enc	Encrypted RXGK_ClientInfo describing the
 *				returned token (use gss_unwrap to decrypt).
 */
static afs_int32
negoclient_send_token(struct rxgk_gss_isc_state *isc,
		      struct rx_connection *conn, RXGK_StartParams *params,
		      RXGK_Data *clientinfo_enc)
{
    afs_uint32 major = 0, minor = 0;
    afs_int32 code;

    RXGK_Data rxgk_send_token;
    RXGK_Data opaque_in;
    RXGK_Data opaque_out;

    rxgk_send_token.val = isc->gss_send_token.value;
    rxgk_send_token.len = isc->gss_send_token.length;

    memset(&opaque_in, 0, sizeof(opaque_in));
    memset(&opaque_out, 0, sizeof(opaque_out));

    if (isc->rxgk_recv_token.val) {
	/*
	 * We're allocating a new rxgk_recv_token now. Make sure there isn't
	 * already a buffer allocated for it; since any buffer from a previous
	 * pass should have already been freed.
	 */
	code = misc_error();
	goto done;
    }

    /* Free clientinfo_enc just in case it was allocated in a previous pass. */
    xdrfree_RXGK_Data(clientinfo_enc);
    memset(clientinfo_enc, 0, sizeof(*clientinfo_enc));

    code = RXGK_GSSNegotiate(conn, params, &rxgk_send_token, &opaque_in,
			     &isc->rxgk_recv_token, &opaque_out, &major,
			     &minor, clientinfo_enc);
    if (code != 0) {
	goto done;
    }
    code = gss2rxgk_error("gss_accept_sec_context (remote)", major, minor);
    if (code != 0) {
	goto done;
    }
    if (opaque_out.len > 0) {
	ViceLog(0, ("rxgk: error: The rxgk server gave us %u bytes of opaque "
		    "data for an additional negotiation round trip. We do not "
		    "support this yet; bailing out.\n",
		    (unsigned)opaque_out.len));
	code = EPROTONOSUPPORT;
	goto done;
    }

 done:
    xdrfree_RXGK_Data(&opaque_out);
    (void)gss_release_buffer(&minor, &isc->gss_send_token);
    memset(&isc->gss_send_token, 0, sizeof(isc->gss_send_token));
    return code;
}

/**
 * Use an rxnull connection to perform GSS negotiation to obtain an rxgk token.
 *
 * Obtain a token over the RXGK negotiation service, for the GSS hostbased
 * principal of service sname on the host given in hostname at the IPv4
 * address in addr (host byte order) and the indicated port (also HBO),
 * for RXGK_Level level.
 *
 * Returns information about the token in the supplied TokenInfo object, and
 * the master key of the token in return_k0, and the token itself in
 * return_token.
 *
 * @param[in] conn	The rx connection upon which GSS negotiation will be
 *			performed. Must be an rxnull connection.
 * @param[in] target	The host-based service name that is the target
 *			principal of the GSS negotiation (e.g.
 *			"afs-rxgk@_afs.cell").
 * @param[in] level	The security level for which the obtained token will
 *			be valid.
 * @param[out] return_info	Information describing the obtained token.
 * @param[out] return_k0	The master key of the returned token.
 * @param[out] return_token	The returned token.
 * @return rx error codes, errno codes.
 */
afs_int32
rxgk_NegotiateClientToken(struct rx_connection *conn, char *target,
			  RXGK_Level level, RXGK_TokenInfo *return_info,
			  RXGK_Data *return_k0, RXGK_Data *return_token)
{
    gss_buffer_desc k0;
    gss_ctx_id_t gss_ctx = GSS_C_NO_CONTEXT;
    gss_name_t target_name = GSS_C_NO_NAME;
    afs_uint32 dummy;

    RXGK_StartParams params;
    RXGK_ClientInfo clientinfo;
    RXGK_Data clientinfo_enc;

    struct rxgk_gss_isc_state isc;
    afs_int32 code;

    memset(&k0, 0, sizeof(k0));
    memset(&params, 0, sizeof(params));
    memset(&clientinfo, 0, sizeof(clientinfo));
    memset(&clientinfo_enc, 0, sizeof(clientinfo_enc));
    memset(&isc, 0, sizeof(isc));

    memset(return_info, 0, sizeof(*return_info));
    memset(return_k0, 0, sizeof(*return_k0));
    memset(return_token, 0, sizeof(*return_token));

    /* Make sure we have an rxnull conn, and we're pointed to the right service
     * id. */
    if (rx_SecurityClassOf(conn) != RX_SECIDX_NULL ||
	rx_ServiceIdOf(conn) != RXGK_SERVICE_ID) {
	code = RXGK_INCONSISTENCY;
	goto done;
    }

    code = import_name(target, &target_name);
    if (code != 0) {
	goto done;
    }

    code = fill_start_params(&params, level);
    if (code != 0)
	goto done;

    /* Keep going as long as our local gss_init_sec_context says we need to
     * keep calling it. */
    do {
	code = negoclient_isc(&isc, &gss_ctx, target_name);
	if (code != 0) {
	    goto done;
	}

	if (isc.gss_send_token.length > 0) {
	    /* If our local gss_init_sec_context says we need to send some data
	     * to the server, then send it. */
	    code = negoclient_send_token(&isc, conn, &params, &clientinfo_enc);
	    if (code != 0) {
		goto done;
	    }
	}
    } while ((isc.major & GSS_S_CONTINUE_NEEDED) != 0);

    code = decode_clientinfo(gss_ctx, &clientinfo_enc, &clientinfo);
    if (code != 0) {
	goto done;
    }

    code = check_clientinfo(gss_ctx, &clientinfo, &params);
    if (code != 0) {
	goto done;
    }

    code = rxgk_make_k0(gss_ctx, &params.client_nonce,
			&clientinfo.server_nonce, clientinfo.enctype,
			&k0);
    if (code != 0) {
	goto done;
    }

    /* Copy data for output */
    return_info->enctype = clientinfo.enctype;
    return_info->level = clientinfo.level;
    return_info->lifetime = clientinfo.lifetime;
    return_info->bytelife = clientinfo.bytelife;
    return_info->expiration = clientinfo.expiration;

    return_token->val = xdr_alloc(clientinfo.token.len);
    if (return_token->val == NULL) {
	code = misc_error();
	goto done;
    }
    memcpy(return_token->val, clientinfo.token.val, clientinfo.token.len);
    return_token->len = clientinfo.token.len;

    code = rx_opaque_populate(return_k0, k0.value, k0.length);
    if (code != 0) {
	code = misc_error();
	goto done;
    }

 done:
    (void)gss_release_buffer(&dummy, &k0);
    (void)gss_delete_sec_context(&dummy, &gss_ctx, GSS_C_NO_BUFFER);
    (void)gss_release_name(&dummy, &target_name);

    xdrfree_RXGK_StartParams(&params);
    xdrfree_RXGK_ClientInfo(&clientinfo);
    xdrfree_RXGK_Data(&clientinfo_enc);

    xdrfree_RXGK_Data(&isc.rxgk_recv_token);
    (void)gss_release_buffer(&dummy, &isc.gss_send_token);

    if (code != 0) {
	memset(return_info, 0, sizeof(*return_info));

	xdrfree_RXGK_Data(return_k0);
	memset(return_k0, 0, sizeof(*return_k0));

	xdrfree_RXGK_Data(return_token);
	memset(return_token, 0, sizeof(*return_token));
    }

    return code;
}
#endif /* AFS_RXGK_GSS_ENV */

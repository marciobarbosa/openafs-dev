/* rxgk/rxgk_procs.c - Server-side RPC procedures for RXGK */
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

/*
 * Server-side RPC procedures for RXGK.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#ifdef AFS_RXGK_GSS_ENV

#include <rx/rx.h>
#include <rx/rx_identity.h>
#include <rx/rxgk.h>

#include "rxgk_private.h"

afs_int32
SRXGK_GSSNegotiate(struct rx_call *z_call, RXGK_StartParams *client_start,
		   RXGK_Data *input_token_buffer, RXGK_Data *opaque_in,
		   RXGK_Data *output_token_buffer, RXGK_Data *opaque_out,
		   afs_uint32 *gss_major_status, afs_uint32 *gss_minor_status,
		   RXGK_Data *rxgk_info)
{
    /* The actual backend for this routine is in rxgk_gss.c. */
    return SGSSNegotiate(z_call, client_start, input_token_buffer, opaque_in,
			 output_token_buffer, opaque_out, gss_major_status,
			 gss_minor_status, rxgk_info);
}


afs_int32
SRXGK_CombineTokens(struct rx_call *z_call, RXGK_Data *token0,
		    RXGK_Data *token1, RXGK_CombineOptions *options,
		    RXGK_Data *new_token, RXGK_TokenInfo *info)
{
    /*
     * This RPC is defined by the base rxgk spec, but no meaning is given for
     * the combined tokens in AFS, and nothing in AFS calls this RPC. So just
     * pretend it doesn't exist.
     */
    return RXGEN_OPCODE;
}

afs_int32
SRXGK_AFSCombineTokens(struct rx_call *z_call, RXGK_Data *user_tok,
		       RXGK_Data *cm_tok, RXGK_CombineOptions *options,
		       afsUUID *destination, RXGK_Data *new_token,
		       RXGK_TokenInfo *info)
{
    struct rx_connection *conn;
    struct rxgk_sconn *sc;
    afs_int32 idx;

    conn = rx_ConnectionOf(z_call);
    idx = rx_SecurityClassOf(conn);
    if (idx != RX_SECIDX_GK) {
	/* For non-rxgk conns, just pretend this RPC doesn't exist. */
	return RXGEN_OPCODE;
    }

    sc = rx_GetSecurityData(conn);
    if (sc->level == RXGK_LEVEL_CLEAR) {
	/* The rxgk spec prohibits AFSCombineTokens calls over CLEAR conns. */
	return RXGK_NOTAUTH;
    }

    if (cm_tok->len != 0) {
	/* We don't support combining with cache manager tokens yet. */
	return RXGK_NOTAUTH;
    }

    /*
     * For now, just always report that the destination fileserver doesn't
     * support rxgk. We indicate this by returning an empty token, and blanked
     * tokeninfo.
     */
    memset(new_token, 0, sizeof(*new_token));
    memset(info, 0, sizeof(*info));
    return 0;
}

#endif /* AFS_RXGK_GSS_ENV */

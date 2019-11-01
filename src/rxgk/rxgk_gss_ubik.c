/* rxgk/rxgk_gss_ubik.c - RXGK routines that interface with the GSS-API and
 * ubik */
/*
 * Copyright (c) 2019 Sine Nomine Associates
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

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#ifdef AFS_RXGK_GSS_ENV

#include <ubik.h>
#include <rx/rxgk.h>

struct args_rxgk_NegotiateClientToken {
    char *target;
    RXGK_Level level;
    RXGK_TokenInfo *return_info;
    RXGK_Data *return_k0;
    RXGK_Data *return_token;
};

static afs_int32
call_rxgk_NegotiateClientToken(struct ubik_callrock_info *info, void *rock)
{
    struct args_rxgk_NegotiateClientToken *args = rock;
    return rxgk_NegotiateClientToken(info->conn, args->target, args->level,
				     args->return_info, args->return_k0,
				     args->return_token);
}

afs_int32
ubik_rxgk_NegotiateClientToken(struct ubik_client *uclient, char *target,
			       RXGK_Level level, RXGK_TokenInfo *return_info,
			       RXGK_Data *return_k0, RXGK_Data *return_token)
{
    struct args_rxgk_NegotiateClientToken args;
    memset(&args, 0, sizeof(args));
    args.target = target;
    args.level = level;
    args.return_info = return_info;
    args.return_k0 = return_k0;
    args.return_token = return_token;

    return ubik_CallRock(uclient, 0, call_rxgk_NegotiateClientToken, &args);
}

struct args_rxgk_CombineSingleClientSecObj {
    afsUUID *client_uuid;
    afsUUID *server_uuid;
    struct rx_securityClass **a_sc;
};

static afs_int32
call_rxgk_CombineSingleClientSecObj(struct ubik_callrock_info *info, void *rock)
{
    struct args_rxgk_CombineSingleClientSecObj *args = rock;
    return rxgk_CombineSingleClientSecObj(info->conn, args->client_uuid,
					  args->server_uuid, args->a_sc);
}

afs_int32
ubik_rxgk_CombineSingleClientSecObj(struct ubik_client *uclient,
				    afsUUID *client_uuid,
				    afsUUID *server_uuid,
				    struct rx_securityClass **a_sc)
{
    struct args_rxgk_CombineSingleClientSecObj args;
    memset(&args, 0, sizeof(args));
    args.client_uuid = client_uuid;
    args.server_uuid = server_uuid;
    args.a_sc = a_sc;

    return ubik_CallRock(uclient, 0, call_rxgk_CombineSingleClientSecObj,
			 &args);
}
#endif /* AFS_RXGK_GSS_ENV */

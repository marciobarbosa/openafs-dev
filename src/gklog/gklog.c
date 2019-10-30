/*
 * Copyright (C) 1990,1991,2014 by the Massachusetts Institute of Technology.
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
 * gklog: Like aklog, except uses GSS to acquire rxgk tokens.
 *
 * Currently, this is a very stripped-down variant of aklog. We do not (yet)
 * support: logging to multiple cells at once, logging to a path, .xlog,
 * akimpersonate, etc.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <afs/ktc.h>
#include <afs/token.h>

#include <afs/auth.h>
#include <afs/cellconfig.h>
#include <afs/com_err.h>
#include <afs/dirpath.h>
#include <afs/ptserver.h>
#include <ubik.h>

#include <rx/rxgk.h>

#include <sys/errno.h>

static char *progname;

static int
get_cellconfig(struct afsconf_dir *configdir, char *cell,
	       struct afsconf_cell *cellconfig, char **local_cell)
{
    int status = 0;

    memset(cellconfig, 0, sizeof(*cellconfig));

    *local_cell = malloc(MAXCELLCHARS);
    if (*local_cell == NULL) {
	fprintf(stderr, "%s: Can't allocate memory for local cell name\n",
		progname);
	exit(1);
    }

    if (cell != NULL && cell[0] == '\0') {
	/* Use the local cell */
	cell = NULL;
    }

    /* This function modifies 'cell' by passing it through lcstring */
    if (afsconf_GetCellInfo(configdir, cell, AFSCONF_VLDBSERVICE, cellconfig)) {
	if (cell != NULL) {
	    fprintf(stderr, "%s: Can't get information about cell %s.\n",
		    progname, cell);
	} else {
	    fprintf(stderr, "%s: Can't get information about the local cell.\n",
		    progname);
	}
	status = 1;
    } else if (afsconf_GetLocalCell(configdir, *local_cell, MAXCELLCHARS)) {
	fprintf(stderr, "%s: can't determine local cell.\n", progname);
	exit(1);
    }

    return(status);
}

static afs_int64
get_viceid(struct afsconf_dir *configdir, char *cell,
	   RXGK_TokenInfo *info, RXGK_Data *k0_data, RXGK_Data *token_blob)
{
    struct rx_securityClass *sc = NULL;
    afs_int64 viceid = 0;
    rxgk_key k0 = NULL;
    afs_int32 code;
    PrAuthName pran;
    struct ubik_client *uclient = NULL;
    struct afsconf_cell cellconf;

    memset(&pran, 0, sizeof(pran));
    memset(&cellconf, 0, sizeof(cellconf));

    code = afsconf_GetCellInfo(configdir, cell, AFSCONF_PROTSERVICE, &cellconf);
    if (code != 0) {
	afs_com_err(progname, code,
		    "while getting cell info while calculating viceid");
	goto done;
    }

    code = rxgk_make_key(&k0, k0_data->val, k0_data->len, info->enctype);
    if (code != 0) {
	afs_com_err(progname, code,
		    "while constructing k0 while calculating viceid");
	goto done;
    }

    sc = rxgk_NewClientSecurityObject(info->level, info->enctype, k0,
				      token_blob);
    if (sc == NULL) {
	afs_com_err(progname, ENOMEM,
		    "while creating security object while calculating viceid");
	goto done;
    }

    code = ugen_ClientInitSecObj(configdir, &cellconf, PRSRV, sc, RX_SECIDX_GK,
				 &uclient);
    if (code != 0) {
	afs_com_err(progname, code,
		    "while initializing ubik client while calculating viceid");
	goto done;
    }

    code = ubik_PR_WhoAmI(uclient, 0, &viceid, &pran);
    if (code != 0) {
	afs_com_err(progname, code, "while calculating viceid");
	viceid = 0;
	goto done;
    }

 done:
    ubik_ClientDestroy(uclient);
    xdrfree_PrAuthName(&pran);
    rxgk_release_key(&k0);
    return viceid;
}

/*
 * Log to a cell.
 */
static int
auth_to_cell(struct afsconf_dir *configdir, struct afsconf_cell *cellconf)
{
    struct ktc_tokenUnion token;
    struct ktc_setTokenData *btoken = NULL;
    struct token_rxgk *rxgk_token;
    RXGK_TokenInfo info;
    RXGK_Data token_blob;
    RXGK_Data k0;
    char *target = NULL;
    struct ubik_client *uclient = NULL;
    afs_int64 viceid = 0;
    int code;

    memset(&token, 0, sizeof(token));
    memset(&token_blob, 0, sizeof(token_blob));
    memset(&k0, 0, sizeof(k0));

    /* First, try to get any existing tokens, so we can preserve any
     * rxkad tokens that might be sitting there. */
    code = ktc_GetTokenEx(cellconf->name, &btoken);
    if (code != 0 || btoken == NULL) {
	/* If we don't have tokens, build a new set of tokens. */
	btoken = token_buildTokenJar(cellconf->name);
	if (btoken == NULL) {
	    code = ENOMEM;
	    afs_com_err(progname, code, "while building tokens");
	    goto done;
	}
    }

    code = asprintf(&target, "afs-rxgk@_afs.%s", cellconf->name);
    if (code < 0) {
	afs_com_err(progname, code, "while constructing GSS target");
	goto done;
    }

    code = ugen_ClientInitService(configdir, cellconf, AFSCONF_SECOPTS_NOAUTH,
				  RXGK_SERVICE_ID, &uclient);
    if (code != 0) {
	afs_com_err(progname, code, "while initializing ubik client");
	goto done;
    }

    code = ubik_rxgk_NegotiateClientToken(uclient, target, RXGK_LEVEL_CRYPT,
					  &info, &k0, &token_blob);
    if (code != 0) {
	afs_com_err(progname, code, "while acquiring tokens");
	if (code == RX_INVALID_OPERATION || code == RXGEN_OPCODE) {
	    fprintf(stderr, "%s: (Does this cell support rxgk?)\n", progname);
	}
	goto done;
    }

    viceid = get_viceid(configdir, cellconf->name, &info, &k0, &token_blob);

    rxgk_token = &token.ktc_tokenUnion_u.at_gk;
    rxgk_token->gk_viceid = viceid;
    rxgk_token->gk_enctype = info.enctype;
    rxgk_token->gk_level = info.level;
    rxgk_token->gk_lifetime = info.lifetime;
    rxgk_token->gk_bytelife = info.bytelife;
    rxgk_token->gk_expiration = info.expiration;
    rxgk_token->gk_k0.gk_k0_val = k0.val;
    rxgk_token->gk_k0.gk_k0_len = k0.len;
    rxgk_token->gk_token.gk_token_val = token_blob.val;
    rxgk_token->gk_token.gk_token_len = token_blob.len;
    token.at_type = AFSTOKEN_UNION_GK;

    /* replace will replace any other rxgk token if present, or add
     * if none are found.  Exactly the right thing. */
    code = token_replaceToken(btoken, &token);
    if (code) {
	afs_com_err(progname, code, "while processing tokens");
	goto done;
    }

    code = ktc_SetTokenEx(btoken);
    if (code) {
	afs_com_err(progname, code, "while setting tokens");
	goto done;
    }

 done:
    ubik_ClientDestroy(uclient);
    token_FreeSet(&btoken);
    free(target);
    xdrfree_RXGK_Data(&k0);
    xdrfree_RXGK_Data(&token_blob);
    return code;
}

int
main(int argc, char *argv[])
{
    char *cell, *local_cell;
    struct afsconf_cell cellconf;
    struct afsconf_dir *configdir;
    const char *config_path = AFSDIR_CLIENT_ETC_DIRPATH;
    int code;

    progname = argv[0];

    initialize_KTC_error_table();
    initialize_RXGK_error_table();
    initialize_ACFG_error_table();

    memset(&cellconf, 0, sizeof(cellconf));

    if (argc > 2) {
	fprintf(stderr, "%s: We can only log to one cell at a time\n", progname);
	exit(1);
    }
    if (argc == 2) {
	cell = argv[1];
    } else {
	/* With no arguments, we log to the local cell. */
	cell = NULL;
    }

    code = rx_Init(0);
    if (code != 0) {
	afs_com_err(progname, code, "while initializing Rx");
	exit(1);
    }

    if (!(configdir = afsconf_Open(config_path))) {
	fprintf(stderr,
		"%s: can't get afs configuration (afsconf_Open(%s))\n",
		progname, config_path);
	exit(1);
    }

    get_cellconfig(configdir, cell, &cellconf, &local_cell);

    code = auth_to_cell(configdir, &cellconf);
    if (code != 0) {
	fprintf(stderr, "%s: authentication to cell %s failed\n",
		progname, cellconf.name);
	exit(1);
    }

    afsconf_Close(configdir);

    free(local_cell);

    return 0;
}

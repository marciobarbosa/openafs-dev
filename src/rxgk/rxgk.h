/* rxgk.h - External interfaces for RXGK */
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
 * External interfaces for RXGK.
 */

#ifndef OPENAFS_RXGK_H
#define OPENAFS_RXGK_H

/* Pull in the com_err table */
#include <rx/rxgk_errs.h>

/* Pull in the protocol description */
#include <rx/rxgk_int.h>

/* Pull in our basic type definitions */
#include <rx/rxgk_types.h>

/* RX-internal headers we depend on. */
#include <rx/rx_opaque.h>
#include <rx/rx_identity.h>

typedef afs_int32 (*rxgk_getkey_func)(void *rock, afs_int32 *kvno,
				      afs_int32 *enctype, rxgk_key *key);

/* Flags for our rx security stats */
#define RXGK_STATS_UNALLOC 0x1
#define RXGK_STATS_AUTH    0x2

/* Indices for our rx service-specific data. */
#define RXGK_SSPECIFIC_GSSNEGO 2

/* rxgk_server.c */
struct rx_securityClass * rxgk_NewServerSecurityObject(afsUUID *server_uuid,
						       void *getkey_rock,
						       rxgk_getkey_func getkey)
						       AFS_NONNULL((3));

afs_int32 rxgk_ServerGetPeerUUID(struct rx_connection *conn, afsUUID *uuid)
				 AFS_NONNULL();

/* rxgk_client.c */
struct rx_securityClass *rxgk_NewClientSecurityObject(RXGK_Level level,
						      afs_int32 enctype,
						      rxgk_key k0,
						      RXGK_Data *token);
afs_int32 rxgk_CombineSingleClientSecObj(struct rx_connection *vl_rxconn,
					 afsUUID *client_uuid,
					 afsUUID *server_uuid,
					 struct rx_securityClass **a_sc)
					 AFS_NONNULL((1,3,4));

/* rxgk_crypto_IMPL.c (currently rfc3961 is the only IMPL) */
afs_int32 rxgk_make_key(rxgk_key *key_out, void *raw_key, afs_uint32 length,
			afs_int32 enctype) AFS_NONNULL();
afs_int32 rxgk_copy_key(rxgk_key key_in, rxgk_key *key_out) AFS_NONNULL();
afs_int32 rxgk_random_key(afs_int32 *enctype, rxgk_key *key_out) AFS_NONNULL();
void rxgk_release_key(rxgk_key *key) AFS_NONNULL();
afs_int32 rxgk_mic_length(rxgk_key key, size_t *out) AFS_NONNULL();
afs_int32 rxgk_mic_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
			  RXGK_Data *out) AFS_NONNULL();
afs_int32 rxgk_check_mic_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
				RXGK_Data *mic) AFS_NONNULL();
afs_int32 rxgk_encrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
			      RXGK_Data *out) AFS_NONNULL();
afs_int32 rxgk_decrypt_in_key(rxgk_key key, afs_int32 usage, RXGK_Data *in,
			      RXGK_Data *out) AFS_NONNULL();
afs_int32 rxgk_derive_tk(rxgk_key *tk, rxgk_key k0, afs_uint32 epoch,
			 afs_uint32 cid, struct afs_time64 *start_time,
			 afs_uint32 key_number) AFS_NONNULL();
afs_int32 rxgk_afscombine1_keydata(struct rx_opaque *combined_keydata,
				   afs_int32 combined_enctype, struct rx_opaque
				   *k1_keydata, afs_int32 k1_enctype,
				   afsUUID *destination) AFS_NONNULL();
afs_int32 rxgk_afscombine1_key(rxgk_key *combined_key,
			       afs_int32 combined_enctype, rxgk_key k1,
			       afsUUID *destination) AFS_NONNULL();
afs_int32 rxgk_cipher_expansion(rxgk_key k0, afs_uint32 *len_out) AFS_NONNULL();
afs_int32 rxgk_nonce(RXGK_Data *nonce, afs_uint32 len) AFS_NONNULL();
int rxgk_enctype_better(afs_int32 old_enctype, afs_int32 new_enctype);
afs_int32 rxgk_choose_enctype(RXGK_Enctypes *enctypes, afs_int32 *a_enctype)
			      AFS_NONNULL();

/* rxgk_gss.c */
afs_int32 rxgk_NegotiateClientToken(struct rx_connection *conn, char *target,
				    RXGK_Level level,
				    RXGK_TokenInfo *return_info,
				    RXGK_Data *return_k0,
				    RXGK_Data *return_token) AFS_NONNULL();

struct rxgk_gss_service_info {
    /* The host-based service name that will be the GSS acceptor identity (e.g.
     * afs-rxgk@_afs.example.com). */
    char *acceptor;

    /* Path to a krb5 keytab containing the GSS acceptor creds (optional). */
    char *keytab;

    /* Callback to get the cell-wide long-term key to use for encrypting
     * tokens. */
    rxgk_getkey_func getkey;
    void *getkey_rock;

    /* Callback to get the fileserver-specific key to use for encrypting tokens
     * for AFSCombineTokens. */
    rxgk_getfskey_func getfskey;
    void *getfskey_rock;
};
afs_int32 rxgk_setup_gss_service(struct rx_service *svc,
				 struct rxgk_gss_service_info *info)
				 AFS_NONNULL();

/* rxgk_gss_ubik.c */
struct ubik_client;
afs_int32 ubik_rxgk_NegotiateClientToken(struct ubik_client *uclient,
					 char *target, RXGK_Level level,
					 RXGK_TokenInfo *return_info,
					 RXGK_Data *return_k0,
					 RXGK_Data *return_token)
					 AFS_NONNULL();
afs_int32 ubik_rxgk_CombineSingleClientSecObj(struct ubik_client *uclient,
					      afsUUID *client_uuid,
					      afsUUID *server_uuid,
					      struct rx_securityClass **a_sc)
					      AFS_NONNULL((1,3,4));

/* rxgk_token.c */
afs_int32 rxgk_make_token(struct rx_opaque *out, RXGK_TokenInfo *info,
			  struct rx_opaque *k0, RXGK_PrAuthName *identities,
			  int nids, rxgk_key key, afs_int32 kvno,
			  afs_int32 enctype) AFS_NONNULL((1,2,3,6));
afs_int32 rxgk_print_token(struct rx_opaque *out, RXGK_TokenInfo *input_info,
			   struct rx_opaque *k0, rxgk_key key, afs_int32 kvno,
			   afs_int32 enctype) AFS_NONNULL();
afs_int32 rxgk_print_token_and_key(struct rx_opaque *out,
                                   RXGK_TokenInfo *input_info, rxgk_key key,
                                   afs_int32 kvno, afs_int32 enctype,
                                   rxgk_key *k0_out) AFS_NONNULL();

/* rxgk_util.c */

/* flags for rxgk_524_conv_id */
#define RXGK_524CONV_DISABLE_DOTCHECK (0x1)

afs_int32 rxgk_524_conv_id(struct rx_identity *gss_id, afs_uint32 flags,
			   struct rx_identity **a_k4id) AFS_NONNULL();
afs_int32 rxgk_krb5_to_gss(char *krb5_princ, struct rx_opaque *gss_data)
			   AFS_NONNULL();

#endif /* OPENAFS_RXGK_H */

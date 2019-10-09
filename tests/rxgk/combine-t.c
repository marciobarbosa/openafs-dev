/* Test the afscombine code inside rxgk. */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <tests/tap/basic.h>
#include <assert.h>

#include <rx/rx_identity.h>
#include <rx/rxgk.h>
#include <afs/rfc3961.h>

#include "common.h"

static struct {
    afs_int32 k1_enctype;
    struct rx_opaque k1_keydata;
    afs_int32 combined_enctype;
    struct rx_opaque combined_keydata;
    afsUUID destination;
} tests[] = {

#define TCASE(k0_enctype, k0_key, combined_enctype, combined_key) \
    { (k0_enctype), \
      { sizeof(k0_key)-1, (k0_key) }, \
      (combined_enctype), \
      { sizeof(combined_key)-1, (combined_key) }, \
      { 0x8484c962, 0x5d1d, 0x4558, 0xb6, 0x52, \
	{ 0x56, 0xa5, 0x1e, 0x44, 0x25, 0x70 } \
      } \
    }

    TCASE(ETYPE_AES128_CTS_HMAC_SHA1_96,
	  "\xb1\xc2\xd1\xf3\xa5\x98\xfa\xb5\x77\x5f\x86\x9b\x04\x88\x88\xca",
	  ETYPE_AES128_CTS_HMAC_SHA1_96,
	  "\x87\x01\xca\xa5\x18\x36\xf9\x1c\x2d\xe0\xb2\x0d\x41\xfe\x6c\x4c"),

    TCASE(ETYPE_AES128_CTS_HMAC_SHA1_96,
	  "\xb2\xc2\xd1\xf3\xa5\x98\xfa\xb5\x77\x5f\x86\x9b\x04\x88\x88\xca",
	  ETYPE_AES256_CTS_HMAC_SHA1_96,
	  "\x13\x9c\x07\x7d\xdf\x68\xfe\x98\xe7\xc7\xf8\x27\xc1\xbe\xd7\x2d"
	  "\xeb\x1d\xba\xe0\xbb\xfe\xd3\x25\x1b\x30\xd7\x0d\x4b\xac\xe8\xdc"),

#undef TCASE

};

static const int n_tests = sizeof(tests)/sizeof(tests[0]);

static void
key2data(rxgk_key key, struct rx_opaque *data)
{
    struct key_impl {
	krb5_context ctx;
	krb5_keyblock key;
    };
    krb5_keyblock *keyblock = &((struct key_impl *)key)->key;
    data->len = keyblock->keyvalue.length;
    data->val = keyblock->keyvalue.data;
}

static void
key2enctype(rxgk_key key, afs_int32 *a_enctype)
{
    struct key_impl {
	krb5_context ctx;
	krb5_keyblock key;
    };
    krb5_keyblock *keyblock = &((struct key_impl *)key)->key;
    *a_enctype = krb5_keyblock_get_enctype(keyblock);
}

int
main(void)
{
    int test_i;
    afs_int32 code;

    plan(4*2);

    for (test_i = 0; test_i < n_tests; test_i++) {
	rxgk_key k1 = NULL;
	afs_int32 k1_enctype = tests[test_i].k1_enctype;
	struct rx_opaque *k1_keydata = &tests[test_i].k1_keydata;
	afs_int32 combined_enctype = tests[test_i].combined_enctype;
	struct rx_opaque *combined_keydata = &tests[test_i].combined_keydata;
	afsUUID *destination = &tests[test_i].destination;

	rxgk_key got_key = NULL;
	afs_int32 got_enctype;
	struct rx_opaque got_keydata = RX_EMPTY_OPAQUE;

	code = rxgk_make_key(&k1, k1_keydata->val, k1_keydata->len, k1_enctype);
	is_int(0, code, "[%d] rxgk_make_key returns success", test_i);

	code = rxgk_afscombine1_key(&got_key, combined_enctype, k1,
				    destination);
	is_int(0, code,
	       "[%d] rxgk_afscombine1_key returns success", test_i);

	key2enctype(got_key, &got_enctype);
	key2data(got_key, &got_keydata);

	is_int(combined_enctype, got_enctype,
	       "[%d] rxgk_afscombine1_key gives correct enctype", test_i);
	is_opaque(combined_keydata, &got_keydata,
		  "[%d] rxgk_afscombine1_key gives correct key data", test_i);

	rxgk_release_key(&k1);
	rxgk_release_key(&got_key);
    }

    return 0;
}

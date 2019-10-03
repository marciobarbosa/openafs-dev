/* Test the 524 conversion code inside rxgk */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <tests/tap/basic.h>
#include <assert.h>

#include "rx/rx_identity.h"
#include "rx/rxgk.h"

static void
create_gss_id(char *princ, struct rx_identity **a_rxid)
{
    struct rx_opaque data;
    afs_int32 code;

    memset(&data, 0, sizeof(data));

    code = rxgk_krb5_to_gss(princ, &data);
    assert(code == 0);

    *a_rxid = rx_identity_new(RX_ID_GSS, princ, data.val, data.len);
    assert(*a_rxid != NULL);

    rx_opaque_freeContents(&data);
}

struct tcase {
    char *k5_princ;
    char *k4_princ;
    afs_uint32 flags;
};

static struct tcase princ_tests[] = {
    {
	.k5_princ = "user@EXAMPLE.COM",
	.k4_princ = "user@EXAMPLE.COM",
    },
    {
	.k5_princ = "user/admin@EXAMPLE.COM",
	.k4_princ = "user.admin@EXAMPLE.COM",
    },
    {
	.k5_princ = "user/admin@EXAMPLE.COM",
	.k4_princ = "user.admin@EXAMPLE.COM",
	.flags = RXGK_524CONV_DISABLE_DOTCHECK,
    },
    {
	.k5_princ = "host/e40-po.mit.edu@ATHENA.MIT.EDU",
	.k4_princ = "rcmd.e40-po@ATHENA.MIT.EDU",
    },
    {
	.k5_princ = "ftp/public.example.org@EXAMPLE.ORG",
	.k4_princ = "ftp.public@EXAMPLE.ORG",
    },
    {
	.k5_princ = "zephyr/zephyr@EXAMPLE.NET",
	.k4_princ = "zephyr@EXAMPLE.NET",
    },

    {
	.k5_princ = "user.admin@EXAMPLE.COM",
    },
    {
	.k5_princ = "user.admin@EXAMPLE.COM",
	.k4_princ = "user.admin@EXAMPLE.COM",
	.flags = RXGK_524CONV_DISABLE_DOTCHECK,
    },

    {
	.k5_princ = "user.admin/admin@EXAMPLE.COM",
    },
    {
	.k5_princ = "user.admin/admin@EXAMPLE.COM",
	.k4_princ = "user.admin.admin@EXAMPLE.COM",
	.flags = RXGK_524CONV_DISABLE_DOTCHECK,
    },

    {
	.k5_princ = "user@EXAMPLE.COM@EXAMPLE.NET",
    },
    {
	.k5_princ = "user/foo/bar@EXAMPLE.COM",
    },
    {
	.k5_princ = "ftp/public@EXAMPLE.ORG",
    },

    {0}
};

int
main(void)
{
    int code;
    struct tcase *test;
    struct rx_identity rxid, *dummy = NULL;

    plan(34);

    for (test = princ_tests; test->k5_princ != NULL; test++) {
	struct rx_identity *gss_id = NULL;
	struct rx_identity *k4_id = NULL;
	char *k5_princ = test->k5_princ;
	char *k4_princ = test->k4_princ;
	afs_uint32 flags = test->flags;

	create_gss_id(k5_princ, &gss_id);
	code = rxgk_524_conv_id(gss_id, flags, &k4_id);

	if (k4_princ != NULL) {
	    is_int(code, 0, "rxgk_524_conv_id(0x%x) for %s succeeds", flags, k5_princ);

	    is_int(k4_id->kind, RX_ID_KRB4,
		   "rxgk_524_conv_id for %s yields RX_ID_KRB4", k5_princ);

	    is_string(k4_princ, k4_id->displayName,
		      "rxgk_524_conv_id for %s converts to %s", k5_princ, k4_princ);
	} else {
	    ok(code != 0, "rxgk_524_conv_id(0x%x) for %s fails", flags, k5_princ);
	}
	rx_identity_free(&gss_id);
	rx_identity_free(&k4_id);
    }

    memset(&rxid, 0, sizeof(rxid));
    rxid.kind = RX_ID_GSS;
    rxid.exportedName.val = "\x04\x01\x00\x0b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
    rxid.exportedName.len = 15;
    code = rxgk_524_conv_id(&rxid, 0, &dummy);
    ok(code != 0, "rxgk_524_conv_id for short exportedName fails (15)");

    memset(&rxid, 0, sizeof(rxid));
    rxid.kind = RX_ID_GSS;
    rxid.exportedName.val = "\x04\x01\x00\x0b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x00\x00\x00\x00";
    rxid.exportedName.len = 19;
    code = rxgk_524_conv_id(&rxid, 0, &dummy);
    ok(code != 0, "rxgk_524_conv_id for short exportedName fails (19)");

    memset(&rxid, 0, sizeof(rxid));
    rxid.kind = RX_ID_GSS;
    rxid.exportedName.val = "\x04\x01\x00\x0b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x00\x00\x00\x05";
    rxid.exportedName.len = 20;
    code = rxgk_524_conv_id(&rxid, 0, &dummy);
    ok(code != 0, "rxgk_524_conv_id for short exportedName fails (20)");

    {
	struct rx_identity *gss_id = NULL;
	create_gss_id("user@EXAMPLE.COM", &gss_id);
	((char*)gss_id->exportedName.val)[1] = '\x02';
	code = rxgk_524_conv_id(gss_id, 0, &dummy);
	rx_identity_free(&gss_id);
	ok(code != 0, "rxgk_524_conv_id for bad-prefix exportedName fails");
    }

    memset(&rxid, 0, sizeof(rxid));
    rxid.kind = RX_ID_SUPERUSER;
    code = rxgk_524_conv_id(&rxid, 0, &dummy);
    ok(code != 0, "rxgk_524_conv_id for non-gss type fails");

    rx_identity_free(&dummy);

    return 0;
}

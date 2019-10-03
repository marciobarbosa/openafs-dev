/* Test the rxgk code to generate GSS names from krb5 princs. */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <tests/tap/basic.h>
#include <assert.h>

#include "rx/rxgk.h"

#include "common.h"

struct tcase {
    char *k5_princ;
    struct rx_opaque gss_data;
};

static struct tcase gss_tests[] = {

#define TCASE(princ, data) \
    { (princ), { sizeof(data)-1, (data) } }

    TCASE("user@EXAMPLE.COM",
	  "\x04\x01\x00\x0b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
	  "\x00\x00\x00\x10user@EXAMPLE.COM"),
    TCASE("user/admin@EXAMPLE.COM",
	  "\x04\x01\x00\x0b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
	  "\x00\x00\x00\x16user/admin@EXAMPLE.COM"),

#undef TCASE

    {0}
};

int
main(void)
{
    int code;
    struct tcase *test;

    plan(4);

    for (test = gss_tests; test->k5_princ != NULL; test++) {
	struct rx_opaque gss_got;

	memset(&gss_got, 0, sizeof(gss_got));

	code = rxgk_krb5_to_gss(test->k5_princ, &gss_got);
	is_int(0, code,
	       "[%s] rxgk_krb5_to_gss returned success", test->k5_princ);

	is_opaque(&test->gss_data, &gss_got,
		  "[%s] rxgk_krb5_to_gss returned correct data",
		  test->k5_princ);

	rx_opaque_freeContents(&gss_got);
    }

    return 0;
}

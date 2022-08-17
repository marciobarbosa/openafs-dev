/*
 * Copyright (c) 2012 Your File System Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include "common.h"

#include <opr/time64.h>

int
main(int argc, char **argv)
{
    struct afs_time64 got64;
    struct afs_time64 val64;
    struct timeval tv;
    time_t got;
    time_t now;
    int code;

    plan(29);

    code = opr_time64_fromSecs(1337065355, &got64);
    is_int(0, code, "opr_time64_fromSecs succeeds");
    is_int64(13370653550000000LL, got64.clunks, "fromSecs");

    code = opr_time64_fromSecs(922337203686LL, &got64);
    is_int(ERANGE, code, "opr_time64_fromSecs fails with ERANGE (+)");

    code = opr_time64_fromSecs(922337203685LL, &got64);
    is_int(0, code, "opr_time64_fromSecs succeeds (+ limit)");
    is_int64(9223372036850000000LL, got64.clunks, "fromSecs");

    code = opr_time64_fromSecs(-922337203686LL, &got64);
    is_int(ERANGE, code, "opr_time64_fromSecs fails with ERANGE (-)");

    code = opr_time64_fromSecs(-922337203685LL, &got64);
    is_int(0, code, "opr_time64_fromSecs succeeds (- limit)");
    is_int64(-9223372036850000000LL, got64.clunks, "fromSecs");

    tv.tv_sec = 1337065355;
    tv.tv_usec = 999999;
    code = opr_time64_fromTimeval(&tv, &got64);
    is_int(0, code, "opr_time64_fromTimeval succeeds");
    is_int64(13370653559999990LL, got64.clunks, "fromTimeval");

    got64.clunks = 13370653550000000LL;
    got = opr_time64_toSecs(&got64);
    is_int(1337065355, got, "toSecs");

    got64.clunks = 13370653569999999LL;
    got = opr_time64_toSecs(&got64);
    is_int(1337065356, got, "toSecs (truncate)");

    got64.clunks = 13370653550000000LL;
    val64.clunks = 13370653550000000LL;
    is_int(0, opr_time64_cmp(&got64, &val64), "cmp(==)");

    got64.clunks = 13370653550000001LL;
    val64.clunks = 13370653550000000LL;
    is_int(1, opr_time64_cmp(&got64, &val64), "cmp(+>+)");

    got64.clunks = 13370653550000001LL;
    val64.clunks = 13370653550000002LL;
    is_int(-1, opr_time64_cmp(&got64, &val64), "cmp(+<+)");

    got64.clunks = 13370653550000001LL;
    val64.clunks = -1;
    is_int(1, opr_time64_cmp(&got64, &val64), "cmp(+>-)");

    got64.clunks = -922337203685LL;
    val64.clunks = 0;
    is_int(-1, opr_time64_cmp(&got64, &val64), "cmp(-<0)");

    got64.clunks = 13370653551230000LL;
    val64.clunks = 12345678;
    code = opr_time64_add(&got64, &val64);
    is_int(0, code, "opr_time64_add success");
    is_int64(13370653563575678LL, got64.clunks, "opr_time64_add result");


    got64.clunks = 9223372036854775800LL;
    val64.clunks = 8;
    code = opr_time64_add(&got64, &val64);
    is_int(ERANGE, code, "opr_time64_add fails with ERANGE (+)");

    got64.clunks = 9223372036854775800LL;
    val64.clunks = 7;
    code = opr_time64_add(&got64, &val64);
    is_int(0, code, "opr_time64_add success (+ limit)");
    is_int64(9223372036854775807LL, got64.clunks, "opr_time64_add value");


    got64.clunks = -9223372036854775800LL;
    val64.clunks = -9;
    code = opr_time64_add(&got64, &val64);
    is_int(ERANGE, code, "opr_time64_add fails with ERANGE (-)");

    got64.clunks = -9223372036854775800LL;
    val64.clunks = -8;
    code = opr_time64_add(&got64, &val64);
    is_int(0, code, "opr_time64_add success (- limit)");
    is_int64(-9223372036854775807LL - 1LL, got64.clunks, "opr_time64_add value");


    got64.clunks = -9223372036854775800LL;
    val64.clunks = 9223372036854775807LL;
    code = opr_time64_add(&got64, &val64);
    is_int(0, code, "opr_time64_add success (large add)");
    is_int64(7, got64.clunks, "opr_time64_add value");


    code = opr_time64_now(&got64);
    is_int(0, code, "opr_time64_now succeeds");

    got = opr_time64_toSecs(&got64);
    now = time(NULL);
    diag("got: %ld, now: %ld", (long)got, (long)now);
    ok(labs(got - now) < 2, "toSecs(now)");

    return 0;
}

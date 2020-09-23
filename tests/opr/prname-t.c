/*
 * Copyright (c) 2020 Sine Nomine Associates. All rights reserved.
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

#include <tests/tap/basic.h>
#include <afs/opr.h>

#include <string.h>

int
main(void)
{
    char name[64];
    int ret, len;

    plan(12);

    /* regular user */
    memset(name, 0, sizeof(name));
    strcpy(name, "foo");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 0, "Regular user");

    /* foreign user */
    memset(name, 0, sizeof(name));
    strcpy(name, "foo@bar");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 0, "Foreign user");

    /* empty user */
    memset(name, 0, sizeof(name));
    strcpy(name, "");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 1, "Empty user (0 blank characters)");

    /* empty user */
    memset(name, 0, sizeof(name));
    strcpy(name, "   ");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 1, "Empty user (3 blank characters)");

    /* empty foreign user */
    memset(name, 0, sizeof(name));
    strcpy(name, "@bar");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 1, "Empty foreign user (0 blank characters)");

    /* empty foreign user */
    memset(name, 0, sizeof(name));
    strcpy(name, "     @bar");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 1, "Empty foreign user (5 blank characters)");

    /* regular group */
    memset(name, 0, sizeof(name));
    strcpy(name, "owner:foo");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 0, "Regular group");

    /* foreign group */
    memset(name, 0, sizeof(name));
    strcpy(name, "owner:foo@bar");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 0, "Foreign group");

    /* empty group */
    memset(name, 0, sizeof(name));
    strcpy(name, "owner:");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 1, "Empty group (0 blank characters)");

    /* empty group */
    memset(name, 0, sizeof(name));
    strcpy(name, "owner:   ");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 1, "Empty group (3 blank characters)");

    /* empty foreign group */
    memset(name, 0, sizeof(name));
    strcpy(name, "owner:@bar");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 1, "Empty foreign group (0 blank characters)");

    /* empty foreign group */
    memset(name, 0, sizeof(name));
    strcpy(name, "owner:     @bar");
    len = strlen(name);
    ret = opr_prname_isblank(name, len);
    ok(ret == 1, "Empty foreign group (5 blank characters)");

    return 0;
}

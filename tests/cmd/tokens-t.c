/*
 * Copyright 2021, Sine Nomine Associates and others.
 * All Rights Reserved.
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

/*
 * cmd_Split() and cmd_Join() tests.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <roken.h>
#include <afs/cmd.h>
#include <tests/tap/basic.h>
#include <ctype.h>

#include "split-tests.h"
#include "join-tests.h"


/*
 * Avoid newlines and other unprintable chars in the c-tap output.
 */
char *
display_string(char *text)
{
    char *display;
    char *p;

    if (text == NULL)
	text = "(NULL)";
    display = strdup(text);
    if (display == NULL)
	sysbail("strdup");
    for (p = display; *p != '\0'; p++) {
	if (!isprint(*p))
	    *p = '.';
    }
    return display;
}

void
test_split(void)
{
    struct split_test_case *t;
    int code;
    int i;
    int argc = 0;
    char **argv = NULL;
    char *display = NULL;

    for (t = split_test_cases; t->input != NULL; t++) {
	display = display_string(t->input);

	code = cmd_Split(t->input, &argc, &argv);
	switch (t->code) {
	case 0:
	    is_int(code, t->code, "cmd_Split |%s|", display);
	    if (code != 0) {
		skip_block(t->argc + 1, ".. failed to split |%s|, code %d",
			   display, code);
	    } else {
		is_int(argc, t->argc, ".. arg count is %d", t->argc);
		if (argc != t->argc) {
		    skip_block(t->argc, ".. arg count mismatch: %s", t->input);
		} else {
		    for (i = 0; i < t->argc; i++)
			is_string(argv[i], t->argv[i],
				  ".. arg %d is |%s|", i, t->argv[i]);
		}
	    }
	    break;
	case CMD_NOCLOSINGQUOTE:
	    is_int(code, t->code, "cmd_Split |%s| no closing quote", display);
	    break;
	case CMD_NOESCAPEDCHAR:
	    is_int(code, t->code, "cmd_Split |%s| no escaped char", display);
	    break;
	default:
	    sysbail("Invalid test case code: %d", code);
	}
	free(display);
	cmd_FreeSplit(&argv);
    }
}

void
test_join(void)
{
    struct join_test_case *t;
    int code;
    char *output = NULL;
    char *display_in = NULL;
    char *display_out = NULL;

    for (t = join_test_cases; t->argc != -1; t++) {
	display_in = display_string(t->display);
	display_out = display_string(t->output);

	code = cmd_Join(t->argc, t->argv, &output);
	is_int(code, 0, "cmd_Join %s", display_in);
	is_string(output, t->output, ".. output is |%s|", display_out);

	free(output);
	free(display_in);
	free(display_out);
    }
}

int
main(int argc, char **argv)
{
    plan(183);
    test_split();
    test_join();
    return 0;
}

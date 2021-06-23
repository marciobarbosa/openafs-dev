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

struct join_test_case {
    char *display;
    int argc;
    char *argv[16];
    char *output;
} join_test_cases[] =
{
    {
	/*
	 * input:  NULL
	 * expect: ||
	 */
	"(NULL)",
	0, {NULL},
	"",
    },
    {
	/*
	 * input:  ||
	 * expect: |''|
	 */
	"||",
	1, {"", NULL},
	"''",
    },
    {
	/*
	 * input:  ||||
	 * expect: |'' '' ''|
	 */
	"||||",
	3, {"", "", "", NULL},
	"'' '' ''",
    },
    {
	/*
	 * input:  | |  |
	 * expect: |' ' '  '|
	 */
	"| |  |",
	2, {" ", "  ", NULL},
	"' ' '  '",
    },
    {
	/*
	 * input:  | |<tab>|<newline>|
	 * expect: |' ' '<tab>' '<newline>'|
	 */
	"| |<tab>|<newline>|",
	3, {" ", "\t", "\n", NULL},
	"' ' '\t' '\n'",
    },
    {
	/*
	 * input:  |hello|world|
	 * expect: |hello world|
	 */
	"|hello|world|",
	2, {"hello", "world", NULL},
	"hello world",
    },
    {
	/*
	 * input:  |hello,|world!|
	 * expect: |hello, 'world!'|
	 */
	"|hello,|world!|",
	2, {"hello,", "world!", NULL},
	"hello, 'world!'",
    },
    {
	/*
	 * input:  |testing:|one|two|three?|
	 * expect: |testing: one two 'three?'|
	 */
	"|testing:|one|two|three?|",
	4, {"testing:", "one", "two", "three?", NULL},
	"testing: one two 'three?'",
    },
    {
	/*
	 * input:  |args with spaces|and|4|more|args|
	 * expect: |'args with spaces' and 4 more args|
	 */
	"|args with spaces|and|4|more|args|",
	5, {"args with spaces", "and", "4", "more", "args", NULL},
	"'args with spaces' and 4 more args",
    },
    {
	/*
	 * input:  |  args with leadin spaces|and trailing spaces |
	 * expect: |'  args with leadin spaces' 'and trailing spaces '|
	 */
	"|  args with leadin spaces|and trailing spaces |",
	2, {"  args with leadin spaces", "and trailing spaces ", NULL},
	"'  args with leadin spaces' 'and trailing spaces '",
    },
    {
	/*
	 * input:  |'Not all those who wander are lost' - Tolkien|
	 * expect: |''"'"'Not all those who wander are lost'"'"' - Tolkien'|
	 */
	"|'Not all those who wander are lost' - Tolkien|",
	1, {"'Not all those who wander are lost' - Tolkien", NULL},
	"''\"'\"'Not all those who wander are lost'\"'\"' - Tolkien'",
    },
    {
	/*
	 * input:  |"Not all those who wander are lost" - Tolkien|
	 * expect: |'"Not all those who wander are lost" - Tolkien'|
	 */
	"|\"Not all those who wander are lost\" - Tolkien|",
	1, {"\"Not all those who wander are lost\" - Tolkien", NULL},
	"'\"Not all those who wander are lost\" - Tolkien'",
    },
    {
	/*
	 * input:  |this\ is\ one\ long\ arg|
	 * expect: |'this\ is\ one\ long\ arg'|
	 */
	"|this\\ is\\ one\\ long\\ arg|",
	1, {"this\\ is\\ one\\ long\\ arg", NULL},
	"'this\\ is\\ one\\ long\\ arg'",
    },
    {
	/*
	 * input:  |this|is\ two\ args|
	 * expect: |this 'is\ two\ args'|
	 */
	"|this|is\\ two\\ args|",
	2, {"this", "is\\ two\\ args", NULL},
	"this 'is\\ two\\ args'",
    },
    {
	/*
	 * input:  |dont't|worry,|be|happy|
	 * expect: |'dont'"'"'t' worry, be happy|
	 */
	"|dont't|worry,|be|happy|",
	4, {"dont't", "worry,", "be", "happy", NULL},
	"'dont'\"'\"'t' worry, be happy",
    },
    {
	/*
	 * input:  |dont\'t|worry,|be|happy|
	 * expect: |'dont\'"'"'t' worry, be happy|
	 */
	"|dont\\'t|worry,|be|happy|",
	4, {"dont\\'t", "worry,", "be", "happy", NULL},
	"'dont\\'\"'\"'t' worry, be happy",
    },
    {
	/*
	 * input:  |'not|quoted'|
	 * expect: |''"'"'not' 'quoted'"'"''|
	 */
	"|'not|quoted'|",
	2, {"'not", "quoted'", NULL},
	"''\"'\"'not' 'quoted'\"'\"''",
    },
    {
	/*
	 * input:  |don"t worry,|be|happy|
	 * expect: |'don"t worry,' be happy|
	 */
	"|don\"t worry,|be|happy|",
	3, {"don\"t worry,", "be", "happy", NULL},
	"'don\"t worry,' be happy",
    },
    {
	/*
	 * input:  |double with 'single' quotes|
	 * expect: |'double with '"'"'single'"'"' quotes'|
	 */
	"|double with 'single' quotes|",
	1, {"double with 'single' quotes", NULL},
	"'double with '\"'\"'single'\"'\"' quotes'",
    },
    {
	/*
	 * input:  |double with escaped "double" quotes|
	 * expect: |'double with escaped "double" quotes'|
	 */
	"|double with escaped \"double\" quotes|",
	1, {"double with escaped \"double\" quotes", NULL},
	"'double with escaped \"double\" quotes'",
    },
    {
	/*
	 * input:  |double with 'single' and escaped \"double\" quotes|
	 * expect: |'double with '"'"'single'"'"' and escaped \"double\" quotes'|
	 */
	"|double with 'single' and escaped \\\"double\\\" quotes|",
	1, {"double with 'single' and escaped \\\"double\\\" quotes", NULL},
	"'double with '\"'\"'single'\"'\"' and escaped \\\"double\\\" quotes'",
    },
    {
	/*
	 * input:  |single with escaped \"double\" quotes|
	 * expect: |'single with escaped \"double\" quotes'|
	 */
	"|single with escaped \\\"double\\\" quotes|",
	1, {"single with escaped \\\"double\\\" quotes", NULL},
	"'single with escaped \\\"double\\\" quotes'",
    },
    {
	/*
	 * input:  |single with quote-escaped "'"single"'" quotes|
	 * expect: |'single with quote-escaped "'"'"'"single"'"'"'" quotes'|
	 */
	"|single with quote-escaped \"'\"single\"'\" quotes|",
	1, {"single with quote-escaped \"'\"single\"'\" quotes", NULL},
	"'single with quote-escaped \"'\"'\"'\"single\"'\"'\"'\" quotes'",
    },
    {
	/*
	 * input:  |"Not all those who wander are lost" - Tolkien|
	 * expect: |'"Not all those who wander are lost" - Tolkien'|
	 */
	"|\"Not all those who wander are lost\" - Tolkien|",
	1, {"\"Not all those who wander are lost\" - Tolkien", NULL},
	"'\"Not all those who wander are lost\" - Tolkien'",
    },
    {
	/*
	 * input:  |"Not all those who wander are lost"|-|Tolkien|
	 * expect: |'"Not all those who wander are lost"' - Tolkien|
	 */
	"|\"Not all those who wander are lost\"|-|Tolkien|",
	3, {"\"Not all those who wander are lost\"", "-", "Tolkien", NULL},
	"'\"Not all those who wander are lost\"' - Tolkien",
    },

    {NULL, -1, {NULL}, NULL} /* End of tests. */
};

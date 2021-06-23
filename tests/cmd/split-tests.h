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

struct split_test_case {
    int code;
    char *input;
    int argc;
    char *argv[16];
} split_test_cases[] = {

    /*
     * Empty and blank strings.
     */
    {
	/*
	 * input:   ||
	 * expect:  ||
	 */
	0, "",
	0, {NULL}
    },
    {
	/*
	 * input:   |    |
	 * expect:  ||
	 */
	0, "    ",
	0, {NULL}
    },
    {
	/*
	 * input:   |<tab><newline>|
	 * expect:  ||
	 */
	0, "\t\n",
	0, {NULL}
    },

    /*
     * Basic tests.
     */
    {
	/*
	 * input:   |hello world|
	 * expect:  |hello|world|
	 */
	0, "hello world",
	2, {"hello", "world", NULL}
    },
    {
	/*
	 * input:   |hello, world!|
	 * expect:  |hello,|world!|
	 */
	0, "hello, world!",
	2, {"hello,", "world!", NULL}
    },
    {
	/*
	 * input:   |testing: one two   three|
	 * expect:  |testing:|one|two|three|
	 */
	0, "testing: one two   three",
	4, {"testing:", "one", "two", "three", NULL}
    },
    {
	/*
	 * input:   |tabs<tab>and newlines<newline>are whitespace|
	 * expect:  |tabs|and|newlines|are|whitespace|
	 */
	0, "tabs\tand newlines\nare whitespace",
	5, {"tabs", "and", "newlines", "are", "whitespace", NULL}
    },

    /*
     * Simple quotes.
     */
    {
	/*
	 * input:   |'single quotes with spaces' and 4 more args|
	 * expect:  |single quotes with spaces|and|4|more|args|
	 */
	0, "'single quotes with spaces' and 4 more args",
	5, {"single quotes with spaces", "and", "4", "more", "args", NULL}
    },
    {
	/*
	 * input:   |"double quotes with spaces" and 4 more args|
	 * expect:  |double quotes with spaces|and|4|more|args|
	 */
	0, "\"double quotes with spaces\" and 4 more args",
	5, {"double quotes with spaces", "and", "4", "more", "args", NULL}
    },
    {
	/*
	 * input:   |unquoted args 'followed by quoted'|
	 * expect:  |unquoted|args|followed by quoted|
	 */
	0, "unquoted args 'followed by quoted'",
	3, {"unquoted", "args", "followed by quoted", NULL}
    },
    {
	/*
	 * input:   |unquoted args "followed by double quoted"|
	 * expect:  |unquoted|args|followed by double quoted|
	 */
	0, "unquoted args \"followed by double quoted\"",
	3, {"unquoted", "args", "followed by double quoted", NULL}
    },
    {
	/*
	 * input:   |"Not all those who wander are lost" - Tolkien|
	 * expect:  |Not all those who wander are lost|-|Tolkien|
	 */
	0, "\"Not all those who wander are lost\" - Tolkien",
	3, {"Not all those who wander are lost", "-", "Tolkien", NULL}
    },

    /*
     * Escaped spaces.
     */
    {
	/*
	 * input:   |this\ is\ one\ long\ arg|
	 * expect:  |this is one long arg|
	 */
	0, "this\\ is\\ one\\ long\\ arg",
	1, {"this is one long arg", NULL}
    },
    {
	/*
	 * input:   |this is\ two\ args|
	 * expect:  |this|is two args|
	 */
	0, "this is\\ two\\ args",
	2, {"this", "is two args", NULL}
    },

    /*
     * Escaped single quotes.
     */
    {
	/*
	 * input:   |dont\'t worry, be happy|
	 * expect:  |dont't|worry,|be|happy|
	 */
	0, "dont\\'t worry, be happy",
	4, {"dont't", "worry,", "be", "happy", NULL}
    },
    {
	/*
	 * input:   |\'not quoted\'|
	 * expect:  |'not|quoted'|
	 */
	0, "\\'not quoted\\'",
	2, {"'not", "quoted'", NULL}
    },

    /*
     * Embedded quote characters.
     */
    {
	/*
	 * input:   |"don't worry," be happy|
	 * expect:  |don't worry,|be|happy|
	 */
	0, "\"don't worry,\" be happy",
	3, {"don't worry,", "be", "happy", NULL}
    },
    {
	/*
	 * input:   |don"'"t' 'worry, be happy|
	 * expect:  |don't worry,|be|happy|
	 */
	0, "don\"'\"t' 'worry, be happy",
	3, {"don't worry,", "be", "happy", NULL}
    },

    /*
     * Quotes characters are modal.
     */
    {
	/*
	 * input:   |this is three' 'args|
	 * expect:  |this|is|three args|
	 */
	0, "this is three' 'args",
	3, {"this", "is", "three args", NULL}
    },
    {
	/*
	 * input:   |this is t'hree arg's|
	 * expect:  |this|is|three args|
	 */
	0, "this is t'hree arg's",
	3, {"this", "is", "three args", NULL}
    },
    {
	/*
	 * input:   |this is three" "args|
	 * expect:  |this|is|three args|
	 */
	0, "this is three\" \"args",
	3, {"this", "is", "three args", NULL}
    },
    {
	/*
	 * input:   |this is t"hree arg"s|
	 * expect:  |this|is|three args|
	 */
	0, "this is t\"hree arg\"s",
	3, {"this", "is", "three args", NULL}
    },

    /*
     * Nested quotes.
     */
    {
	/*
	 * input:   |"double with 'single' quotes"|
	 * expect:  |double with 'single' quotes|
	 */
	0, "\"double with 'single' quotes\"",
	1, {"double with 'single' quotes", NULL}
    },
    {
	/*
	 * input:   |"double with escaped \"double\" quotes"|
	 * expect:  |double with escaped "double" quotes|
	 */
	0, "\"double with escaped \\\"double\\\" quotes\"",
	1, {"double with escaped \"double\" quotes", NULL}
    },
    {
	/*
	 * input:   |"double with 'single' and escaped \"double\" quotes"|
	 * expect:  |double with 'single' and escaped "double" quotes|
	 */
	0, "\"double with 'single' and escaped \\\"double\\\" quotes\"",
	1, {"double with 'single' and escaped \"double\" quotes", NULL}
    },
    {
	/*
	 * input:   |'single with escaped \"double\" quotes'|
	 * expect:  |single with escaped \"double\" quotes|
	 */
	0, "'single with escaped \\\"double\\\" quotes'",
	1, {"single with escaped \\\"double\\\" quotes", NULL}
    },
    {
	/*
	 * input:   |'single with quote-escaped "'"single"'" quotes'|
	 * expect:  |single with quote-escaped "single" quotes|
	 */
	0, "'single with quote-escaped \"'\"single\"'\" quotes'",
	1, {"single with quote-escaped \"single\" quotes", NULL}
    },
    {
	/*
	 * input:   |'"Not all those who wander are lost" - Tolkien'|
	 * expect:  |"Not all those who wander are lost" - Tolkien|
	 */
	0, "'\"Not all those who wander are lost\" - Tolkien'",
	1, {"\"Not all those who wander are lost\" - Tolkien", NULL}
    },
    {
	/*
	 * input:   |"\"Not all those who wander are lost\" - Tolkien"|
	 * expect:  |"Not all those who wander are lost" - Tolkien|
	 */
	0, "\"\\\"Not all those who wander are lost\\\" - Tolkien\"",
	1, {"\"Not all those who wander are lost\" - Tolkien", NULL}
    },

    /*
     * Missing closing quotes.
     */
    {
	/*
	 * input:   |'|
	 * expect:  CMD_NOCLOSINGQUOTE error.
	 */
	CMD_NOCLOSINGQUOTE, "'",
	0, {NULL}
    },
    {
	/*
	 * input:   |"|
	 * expect:  CMD_NOCLOSINGQUOTE error.
	 */
	CMD_NOCLOSINGQUOTE, "\"",
	0, {NULL}
    },
    {
	/*
	 * input:   |'missing closing single quote|
	 * expect:  CMD_NOCLOSINGQUOTE error.
	 */
	CMD_NOCLOSINGQUOTE, "'missing closing single quote",
	0, {NULL}
    },
    {
	/*
	 * input:   |missing closing 'single quote|
	 * expect:  CMD_NOCLOSINGQUOTE error.
	 */
	CMD_NOCLOSINGQUOTE, "missing closing 'single quote",
	0, {NULL}
    },
    {
	/*
	 * input:   |missing closing single quote'|
	 * expect:  CMD_NOCLOSINGQUOTE error.
	 */
	CMD_NOCLOSINGQUOTE, "missing closing single quote'",
	0, {NULL}
    },
    {
	/*
	 * input:   |"missing closing double quote|
	 * expect:  CMD_NOCLOSINGQUOTE error.
	 */
	CMD_NOCLOSINGQUOTE, "\"missing closing double quote",
	0, {NULL}
    },
    {
	/*
	 * input:   |'""missing closing single quote|
	 * expect:  CMD_NOCLOSINGQUOTE error.
	 */
	CMD_NOCLOSINGQUOTE, "'\"\"missing closing single quote",
	0, {NULL}
    },
    {
	/*
	 * input:   |'backslashes are \'literals\' in single quotes'|
	 * expect:  CMD_NOCLOSINGQUOTE error.
	 */
	CMD_NOCLOSINGQUOTE, "'backslashes are \\'literals\\' in single quotes'",
	0, {NULL}
    },

    /*
     * No escaped character.
     */
    {
	/*
	 * input:   |a character must follow a backslash\|
	 * expect:  CMD_NOESCAPEDCHAR error.
	 */
	CMD_NOESCAPEDCHAR, "a character must follow a backslash\\",
	0, {NULL}
    },

    {-1, NULL, -1, {NULL}} /* End of tests. */
};

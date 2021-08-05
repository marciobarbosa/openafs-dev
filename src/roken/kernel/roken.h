/*
 * Copyright (c) 2021 Sine Nomine Associates. All Rights Reserved.
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

#ifdef AFS_NT40_ENV
#define ROKEN_LIB_FUNCTION
#define ROKEN_LIB_CALL     __cdecl
#define ROKEN_LIB_VARIABLE __declspec(dllexport)
#else
#define ROKEN_LIB_FUNCTION
#define ROKEN_LIB_CALL
#define ROKEN_LIB_VARIABLE
#endif

#ifndef HAVE_STRLCPY
#define strlcpy rk_strlcpy
ROKEN_LIB_FUNCTION size_t ROKEN_LIB_CALL strlcpy (char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCAT
#define strlcat rk_strlcat
ROKEN_LIB_FUNCTION size_t ROKEN_LIB_CALL strlcat (char *, const char *, size_t);
#endif

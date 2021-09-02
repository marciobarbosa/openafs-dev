/*
 * Copyright (c) 2021 Sine Nomine Associates. All rights reserved.
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
 * Memory Management
 *
 * Groups functions responsible for allocating and freeing memory. Intended to
 * be {user,kernel}-space friendly.
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <afs/opr.h>

#ifdef KERNEL
# include <afs/sysincludes.h>
# include <afsincludes.h>
#else
# include <roken.h>
#endif

#ifdef KERNEL
# define MAX_ALLOC_SIZE	4096
#endif

/**
 * Alloc a zero-initialized memory block.
 *
 * On kernel-space, extra space is allocated so we have room to save the size of
 * the block. Doing so, opr_Free() doesn't have to receive this size as an
 * argument and we can keep the same interface for kernel-space and user-space.
 *
 * @param[in] num  number of elements
 * @param[in] size size of each element
 *
 * @return allocated memory block on success; NULL otherwise.
 */
void *
opr_Calloc(size_t num, size_t size)
{
    void *ptr = NULL;
#ifdef KERNEL
    size_t bytes = num * size;
    size_t sz = sizeof(size_t);

    if (bytes == 0) {
	goto done;
    }
    /* save space to store the allocated size */
    bytes += sz;

    if (bytes > MAX_ALLOC_SIZE) {
	goto done;
    }

    ptr = afs_osi_Alloc(bytes);
    if (ptr == NULL) {
	goto done;
    }

    memcpy(ptr, &bytes, sz);
    ptr += sz;
    memset(ptr, 0, bytes - sz);
#else
    ptr = calloc(num, size);
#endif
 done:
    return ptr;
}

/**
 * Alloc a zero-initialized memory block and assert that we succeeded.
 *
 * @param[in] num  number of elements
 * @param[in] size size of each element
 *
 * @return allocated memory block.
 */
void *
opr_CallocAssert(size_t num, size_t size)
{
    void *ptr;

    ptr = opr_Calloc(num, size);
    opr_Assert(ptr != NULL);

    return ptr;
}

/**
 * Deallocate a memory block.
 *
 * On kernel-space, the first bytes store the total size of the block of memory
 * to be released.
 *
 * @param[inout] ptr block of memory to be released
 */
void
opr_Free(void **a_ptr)
{
    void *ptr = *a_ptr;
#ifdef KERNEL
    size_t bytes;
    size_t sz = sizeof(size_t);

    if (ptr == NULL) {
	return;
    }
    ptr -= sz;
    memcpy(&bytes, ptr, sz);
    afs_osi_Free(ptr, bytes);
#else
    free(ptr);
#endif
    *a_ptr = NULL;
}

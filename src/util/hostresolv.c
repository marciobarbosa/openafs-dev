/*
 * Copyright (c) 2016 Sine Nomine Associates. All rights reserved.
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
#include "hostresolv.h"

#ifndef AFS_NT40_ENV

#include <afs/opr.h>
#include <opr/lock.h>
#include <opr/jhash.h>

#ifdef AFS_PTHREAD_ENV

#include <pthread.h>

static opr_mutex_t cache_mutex;
static pthread_once_t cache_init_th = PTHREAD_ONCE_INIT;

#define cache_lock() do { opr_mutex_enter(&cache_mutex); } while (0)
#define cache_unlock() do { opr_mutex_exit(&cache_mutex); } while (0)
#define cache_locked() do { opr_mutex_assert(&cache_mutex); } while (0)

#else

#define cache_lock() do { } while (0)
#define cache_unlock() do { } while (0)
#define cache_locked() do { } while (0)

#endif

static afs_uint32 cache_inited;
static struct opr_dict *cache;	/*!< cache using jhash */
static afs_uint32 cache_size;	/*!< current size of cache */
static time_t next_expire_time;	/*!< next check for expirations */
static time_t greatest_ttl;
static const char hex[] = "0123456789abcdef";

/*!
 * Initialize the cache.
 *
 * This function creates the dictionary that is gonna
 * be used to store the cache entries. The size of this
 * dictionary is specified by HASH_SIZE_LOG2.
 *
 * \param  none
 * \return none
 */
static void
cache_init(void)
{
    cache = opr_dict_Init(opr_jhash_size(HASH_SIZE_LOG2));
    if (cache == NULL) {
	return;
    }
#ifdef AFS_PTHREAD_ENV
    opr_mutex_init(&cache_mutex);
#endif
    cache_inited = 1;
}

/*!
 * Initialize the cache only once.
 *
 * This function initializes the cache only once. If the
 * cache is already initialized, nothing is done.
 *
 * \param  none
 * \return 1 if the cache is initialized. Otherwise, 0.
 */
static afs_uint32
cache_init_once(void)
{
#ifdef AFS_PTHREAD_ENV
    pthread_once(&cache_init_th, cache_init);
#else
    if (cache_inited == 0) {
	cache_init();
    }
#endif
    return cache_inited;
}

/*!
 * Find out the hostname and the ttl of the provided address.
 *
 * This function is responsible to provide the hostname and
 * the dns ttl of the given ip address. This ttl is used to
 * calculate the expiration time of the cache entries.
 *
 * \param[in]  addr    ip address
 * \param[in]  addrlen size of addr
 * \param[in]  af      addr's family (AF_INET or AF_INET6)
 * \param[out] buffer  addr's hostname
 * \param[out] ttl     addr's ttl
 * \return             >= 0 on success
 */
static int
resolve(void *addr, size_t addrlen, int af, char **buffer, time_t * ttl)
{
    int n, code;
    char *bp;
    char qbuf[MAXDNAME + 1];
    union dns_res response;
    u_char c, *cp;
    u_char *data, *end;

    if ((_res.options & RES_INIT) == 0) {
	code = res_init();
	if (code < 0) {
	    goto done;
	}
    }

    code = 0;
    bp = qbuf;
    cp = (u_char *) addr + addrlen - 1;

    switch (af) {
    case AF_INET:
	for (n = 0; n < addrlen; n++, cp--) {
	    c = *cp;
	    if (c >= 100)
		*bp++ = '0' + c / 100;
	    if (c >= 10)
		*bp++ = '0' + (c % 100) / 10;
	    *bp++ = '0' + c % 10;
	    *bp++ = '.';
	}
	strcpy(bp, "in-addr.arpa");
	break;
    case AF_INET6:
	for (n = 0; n < addrlen; n++, cp--) {
	    c = *cp;
	    *bp++ = hex[c & 0xf];
	    *bp++ = '.';
	    *bp++ = hex[c >> 4];
	    *bp++ = '.';
	}
	strcpy(bp, "ip6.arpa");
	break;
    default:
	code = -1;
	goto done;
    }
    /* at this point, qbuf should be equal to ip + suffix. IPv4 example: a.b.c.d
     * => qbuf: d.c.b.a.in-addr.arpa */
    n = res_search(qbuf, C_IN, T_PTR, (void *)&response, sizeof(response));

    if (n <= 0) {
	code = -1;
	goto done;
    }
    if (ntohs(response.hdr.rcode != NOERROR)
	|| ntohs(response.hdr.ancount) < 1) {
	code = -1;
	goto done;
    }

    /* skip unimportant fields */
    data = response.buf + sizeof(HEADER);
    end = response.buf + n;
    data += dn_skipname(data, end) + QFIXEDSZ;
    data += dn_skipname(data, end);
    data += 2 * INT16SZ;
    GETLONG(*ttl, data);	/* ttl */
    data += INT16SZ;
    n = dn_expand(response.buf, end, data, qbuf, sizeof(qbuf));	/* hostname */

    if (n <= 0) {
	code = -1;
	goto done;
    }
    *buffer = strdup(qbuf);

    if (*buffer == NULL) {
	code = -1;
    }
  done:
    return code;
}

/*!
 * Remove the provided entry from the hash.
 *
 * \param[in] hce cache entry
 * \return    none
 */
static void
remove_entry(struct hostname_cache_entry *hce)
{
    opr_queue_Remove(&hce->link);
    free(hce->hostname);
    free(hce);
    cache_size--;
}

/*!
 * Remove the expired entries from the provided bucket.
 *
 * This function goes through every single entry of the given
 * bucket and checks if they are up to date. If not, the
 * expired entries are removed. Some entries might be removed
 * in advance, if some space is necessary. To do so, the
 * current time might be advanced by early_expire.
 *
 * \param[in] index        bucket position
 * \param[in] time         current time
 * \param[in] early_expire offset
 * \return                 none
 */
static_inline void
check_bucket(afs_uint32 index, time_t time, time_t early_expire)
{
    struct hostname_cache_entry *hce;
    struct opr_queue *cursor, *store;

    for (opr_dict_ScanBucketSafe(cache, index, cursor, store)) {
	hce = opr_queue_Entry(cursor, struct hostname_cache_entry, link);
	if (time + early_expire < hce->expires) {
	    if (hce->ttl > greatest_ttl) {
		greatest_ttl = hce->ttl;
	    }
	    continue;
	}
	remove_entry(hce);
    }
}

/*!
 * Check if the cache entries are still up to date.
 *
 * \param[in] time         current time
 * \param[in] early_expire offset
 * \return                 none
 */
static void
check_expirations(time_t time, time_t early_expire)
{
    afs_uint32 index;

    cache_locked();

    if (cache_size == 0) {
	return;
    }
    greatest_ttl = 0;
    for (index = 0; index < opr_jhash_size(HASH_SIZE_LOG2); index++) {
	check_bucket(index, time, early_expire);
    }
}

/*!
 * Remove some entries to create room for new ones.
 *
 * This function is responsible to advance the removal
 * of some entries in order to create room for new ones.
 *
 * \param[in] new_size new cache size after removals
 * \param[in] time     current time
 * \return             none
 */
static void
cache_evict(afs_uint32 new_size, time_t time)
{
    time_t early_ttl = greatest_ttl / 2;

    while (cache_size > new_size) {
	check_expirations(time, greatest_ttl - early_ttl);
	early_ttl = early_ttl / 2;
    }
}

/*!
 * Check if the provided addresses are equal.
 *
 * \param[in] sa      first ip address
 * \param[in] addr    second ip address
 * \param[in] addrlen size of the second ip address
 * \param[in] af      family of the second ip address
 * \return            1 if they are equal. Otherwise, 0.
 */
static int
address_found(struct sockaddr *sa, void *addr, size_t addrlen, int af)
{
    int equal = 0;
    struct sockaddr_in *sa4;
    struct sockaddr_in6 *sa6;

    if (sa->sa_family != af) {
	return 0;
    }
    switch (af) {
    case AF_INET:
	sa4 = (struct sockaddr_in *)sa;
	if (sa4->sin_addr.s_addr == *(afs_uint32 *) addr) {
	    equal = 1;
	}
	break;
    case AF_INET6:
	sa6 = (struct sockaddr_in6 *)sa;
	equal = !memcmp(sa6->sin6_addr.s6_addr, addr, addrlen);
	break;
    }
    return equal;
}

/*!
 * Try to find the given ip in the cache. If not found, create an entry.
 *
 * This function checks if the hostname of the given ip address
 * is stored in the cache. It it is, the entry in question is
 * returned. If not, a new entry is created. If the hostname can
 * not be defined, the formatted ip address will be stored as the
 * hostname and the ttl of this entry will be equal to DEFAULT_TTL
 * (negative cache).
 *
 * \param[in] addr    ip address
 * \param[in] addrlen size of the ip address
 * \param[in] af      ip address family
 * \return            found/created entry
 */
static struct hostname_cache_entry *
cache_find(void *addr, size_t addrlen, int af)
{
    int code, len;
    time_t now, ttl;
    struct hostname_cache_entry *hce;
    struct opr_queue *cursor, *store;
    struct sockaddr *sa;
    const char *p;
    afs_uint32 index;

    hce = NULL;
    now = time(NULL);
    index = opr_jhash_opaque(addr, addrlen, 0);
    index &= opr_jhash_mask(HASH_SIZE_LOG2);

    if (!cache_inited) {
	goto done;
    }
    cache_locked();

    /* check if the cache entries are still up to date */
    if (next_expire_time < now) {
	check_expirations(now, 0);
	next_expire_time = now + DEFAULT_TTL;
    }

    for (opr_dict_ScanBucketSafe(cache, index, cursor, store)) {
	hce = opr_queue_Entry(cursor, struct hostname_cache_entry, link);
	sa = &hce->address.sa;
	if (!address_found(sa, addr, addrlen, af)) {
	    continue;
	}
	if (hce->expires > now) {
	    opr_dict_Promote(cache, index, &hce->link);
	    goto done;
	} else {
	    remove_entry(hce);
	    break;
	}
    }

    /* remove some entries to create room for new ones */
    if (cache_size == MAX_SIZE) {
	cache_evict(MAX_SIZE / 2, now);
    }

    hce = (struct hostname_cache_entry *)calloc(1, sizeof(*hce));
    if (hce == NULL) {
	goto done;
    }
    switch (af) {
    case AF_INET:
	hce->address.sa4.sin_family = af;
	hce->address.sa4.sin_addr.s_addr = *(afs_uint32 *) addr;
	break;
    case AF_INET6:
	hce->address.sa6.sin6_family = af;
	memcpy(hce->address.sa6.sin6_addr.s6_addr, addr, addrlen);
	break;
    }
    code = resolve(addr, addrlen, af, &hce->hostname, &ttl);
    hce->expires = now + ttl;
    if (code < 0) {
	len = (af == AF_INET) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
	hce->hostname = (char *)calloc(len, sizeof(char));
	if (hce->hostname == NULL) {
	    free(hce);
	    hce = NULL;
	    goto done;
	}
	/* negative cache */
	p = inet_ntop(af, addr, hce->hostname, len);
	if (p == NULL) {
	    free(hce->hostname);
	    free(hce);
	    hce = NULL;
	    goto done;
	}
    }
    hce->ttl = ttl;
    if (hce->expires <= now) {
	hce->expires = now + DEFAULT_TTL;
    }
    if (ttl > greatest_ttl) {
	greatest_ttl = ttl;
    }
    opr_dict_Prepend(cache, index, &hce->link);
    cache_size++;
  done:
    return hce;
}

#endif

/*!
 * Get the hostname of the provided ip address.
 *
 * This function provides a caching mechanism to store the
 * hostnames of the IP addresses already resolved.
 *
 * \note This caching mechanism is not supported on
 * 	 Windows yet.
 *
 * \param[in]  addr    ip address
 * \param[in]  addrlen size of the ip address
 * \param[in]  af      ip address family
 * \param[out] buffer  hostname
 * \param[in]  len     size of buffer
 * \return             hostname
 */
char *
util_gethostname(void *addr, size_t addrlen, int af, char *buffer, size_t len)
{
    struct sockaddr *sa;
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    size_t sa_size;
    int code;
#ifndef AFS_NT40_ENV
    struct hostname_cache_entry *hce;
    afs_uint32 inited;
#endif
    if (af != AF_INET && af != AF_INET6) {
	goto done;
    }
    sa = NULL;
    sa_size = 0;
#ifndef AFS_NT40_ENV
    inited = cache_init_once();

    if (inited) {
	cache_lock();
	hce = cache_find(addr, addrlen, af);
	cache_unlock();

	if (hce != NULL) {
	    strlcpy(buffer, hce->hostname, len);
	    goto done;
	}
    }
#else
    if (afs_winsockInit() < 0) {
	goto done;
    }
#endif
    switch (af) {
    case AF_INET:
	sa4.sin_addr.s_addr = *(afs_uint32 *) addr;
	sa = (struct sockaddr *)&sa4;
	sa_size = sizeof(sa4);
	break;
    case AF_INET6:
	memcpy(sa6.sin6_addr.s6_addr, addr, addrlen);
	sa = (struct sockaddr *)&sa6;
	sa_size = sizeof(sa6);
	break;
    }
    sa->sa_family = af;
    code = getnameinfo(sa, sa_size, buffer, len, NULL, 0, 0);
    if (code == 0) {
	goto done;
    }
    inet_ntop(af, addr, buffer, len);
  done:
    return buffer;
}

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <afs/opr.h>
#include <opr/lock.h>
#include <opr/jhash.h>

#include "resolvaddr.h"

#ifdef AFS_PTHREAD_ENV

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
static struct opr_dict *cache;
static afs_uint32 cache_size;
static afs_uint32 next_expire_time;
static time_t greatest_ttl;
static const char hex[] = "0123456789abcdef";

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

static int
resolve_addr(void *addr, size_t addrlen, int af, char **buffer, time_t *ttl)
{
    int n, code;
    char *bp;
    char qbuf[MAXDNAME + 1];
    u_char querybuf[NS_PACKETSZ];
    u_char c, *cp;
    ns_msg handle;
    ns_rr rr;

    if ((_res.options & RES_INIT) == 0) {
	code = res_init();
	if (code < 0) {
	    goto done;
	}
    }
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
    n = res_query(qbuf, C_IN, T_PTR, querybuf, sizeof(querybuf));
    code = ns_initparse(querybuf, n, &handle);

    if (code < 0) {
	goto done;
    }
    code = ns_msg_count(handle, ns_s_an);

    if (code < 0) {
	goto done;
    }
    code = ns_parserr(&handle, ns_s_an, 0, &rr);

    if (code < 0) {
	goto done;
    }
    code = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
			      ns_rr_rdata(rr), qbuf, MAXDNAME);
    if (code < 0) {
	goto done;
    }
    *buffer = strdup(qbuf);

    if (*buffer == NULL) {
	code = -1;
	goto done;
    }
    *ttl = ns_rr_ttl(rr);
  done:
    return code;
}

static void
remove_entry(struct hostname_cache_entry *hce)
{
    opr_queue_Remove(&hce->link);
    free(hce->hostname);
    free(hce);
    cache_size--;
}

static_inline void
check_bucket(afs_uint32 index, time_t time, time_t early_expire)
{
    struct hostname_cache_entry *hce;
    struct opr_queue *cursor, *store;

    for (opr_dict_ScanBucketSafe(cache, index, cursor, store)) {
	hce = opr_queue_Entry(cursor, struct hostname_cache_entry, link);
	if (time + early_expire < hce->expires) {
	    continue;
	}
	remove_entry(hce);
    }
}

static void
check_expirations(time_t time, time_t early_expire)
{
    afs_uint32 index;

    cache_locked();

    if (cache_size == 0) {
	return;
    }
    for (index = 0; index < opr_jhash_size(HASH_SIZE_LOG2); index++) {
	check_bucket(index, time, early_expire);
    }
}

static void
cache_evict(afs_uint32 new_size, time_t time)
{
    time_t early_ttl = greatest_ttl / 2;

    while (cache_size > new_size) {
	check_expirations(time, greatest_ttl - early_ttl);
	early_ttl = early_ttl / 2;
    }
}

int
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
	if (sa4->sin_addr.s_addr == *(afs_uint32 *)addr) {
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

static struct hostname_cache_entry *
cache_find(void *addr, size_t addrlen, int af)
{
    int code;
    time_t now;
    struct hostname_cache_entry *hce;
    struct opr_queue *cursor, *store;
    struct sockaddr *sa;
    afs_uint32 index;

    hce = NULL;
    now = time(NULL);
    index = opr_jhash_opaque(addr, addrlen, 0);
    index &= opr_jhash_mask(HASH_SIZE_LOG2);

    if (!cache_inited) {
	goto done;
    }
    cache_locked();

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

    if (cache_size == MAX_SIZE) {
	cache_evict(MAX_SIZE / 2, now);
    }

    hce = (struct hostname_cache_entry *) calloc(1, sizeof(*hce));
    if (hce == NULL) {
	goto done;
    }
    switch (af) {
    case AF_INET:
	hce->address.sa4.sin_family = af;
	hce->address.sa4.sin_addr.s_addr = *(afs_uint32 *)addr;
	break;
    case AF_INET6:
	hce->address.sa6.sin6_family = af;
	memcpy(hce->address.sa6.sin6_addr.s6_addr, addr, addrlen);
	break;
    }
    code = resolve_addr(addr, addrlen, af, &hce->hostname, &hce->expires);
    if (code < 0) {
	free(hce);
	hce = NULL;
	goto done;
    }
    if (hce->expires <= 0) {
	hce->expires = DEFAULT_TTL;
    }
    if (hce->expires > greatest_ttl) {
	greatest_ttl = hce->expires;
    }
    opr_dict_Prepend(cache, index, &hce->link);
    cache_size++;
  done:
    return hce;
}

char *
opr_resolvaddr(void *addr, size_t addrlen, int af, char *buffer, size_t len)
{
    struct hostname_cache_entry *hce;
    afs_uint32 inited;

    if (af != AF_INET && af != AF_INET6) {
	goto done;
    }
    inited = cache_init_once();

    if (inited) {
	cache_lock();
	hce = cache_find(addr, addrlen, af);
	cache_unlock();

	if (hce != NULL && strlen(hce->hostname) < len) {
	    strlcpy(buffer, hce->hostname, len);
	    return buffer;
	}
    }
  done:
    return NULL;
}

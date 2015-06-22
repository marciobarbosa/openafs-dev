/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * ALL RIGHTS RESERVED
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#ifdef AFS_NT40_ENV
#include <direct.h>
#else
#include <ctype.h>
#endif

#include <opr/jhash.h>
#include "afsutil.h"

#define HASH_BUCKETS_SIZE 512	/* must be a power of 2 */
#define ADDR_HASH(addr) \
    (opr_jhash_int((addr), 0) & (HASH_BUCKETS_SIZE - 1))

static struct host_cache *cache = NULL;
static afs_uint32 cache_count = 0;
#ifdef AFS_PTHREAD_ENV
static pthread_mutex_t cache_mutex;
#endif

struct host_cache_entry {
    afs_uint32 address;
    char *name;
    struct host_cache_entry *next;
};

struct host_cache {
    struct host_cache_entry *hash_table[HASH_BUCKETS_SIZE];
};

/**
 * Lookup the IP address in the hashtable. If not found, create an entry.
 *
 * @param[in] aaddr ipv4 address in network byte order
 *
 * @return host cache entry object
 *   @retval pointer to the found/created hashtable entry success
 *   @retval NULL failure
 */
static struct host_cache_entry *
find_host_cache(afs_uint32 aaddr)
{
    struct host_cache_entry *hce = NULL;
    afs_uint32 i = ADDR_HASH(aaddr);
    char *name;

    if (cache == NULL)
	goto done;

    for (hce = cache->hash_table[i]; hce != NULL; hce = hce->next) {
	if (hce->address == aaddr)
	    break;
    }
    if (hce != NULL)
	return hce;
    hce = calloc(1, sizeof(struct host_cache_entry));
    if (hce == NULL)
	goto done;
    hce->address = aaddr;
    name = hostutil_GetNameByINet(aaddr);
    hce->name = (name != NULL) ? strdup(name) : NULL;
    if (hce->name == NULL) {
	free(hce);
	hce = NULL;
	goto done;
    }
    hce->next = cache->hash_table[i];
    cache->hash_table[i] = hce;
  done:
    return hce;
}

/**
 * Allocate the hash table. If already allocated, no action is needed.
 *
 * The hash table allocated by this function will be used by the function
 * hostutil_GetNameByINetCached in order to speed up subsequent lookups.
 * This function may be called multiple times, but only one global hash
 * table will be allocated.
 *
 * @param none
 *
 * @return none
 */
void
hostutil_InitHostCache(void)
{
#ifdef AFS_PTHREAD_ENV
    pthread_mutex_lock(&cache_mutex);
#endif
    if (cache == NULL) {
	cache = (struct host_cache *)calloc(1, sizeof(struct host_cache));
    }
    cache_count++;
#ifdef AFS_PTHREAD_ENV
    pthread_mutex_unlock(&cache_mutex);
#endif
}

/**
 * Remove the linked list addressed by a specific bucket.
 *
 * This function is called by hostutil_DestroyHostCache. It is
 * responsible to clean up the content addressed by the bucket
 * given as a parameter.
 *
 * @param[in] aentry bucket
 *
 * @return none
 */
static inline void
remove_bucket(struct host_cache_entry *aentry)
{
    struct host_cache_entry *next;

    while (aentry != NULL) {
	next = aentry->next;
	free(aentry->name);
	free(aentry);
	aentry = next;
    }
}

/**
 * Clean up the hash table used by hostutil_GetNameByINetCached.
 *
 * This function should be called when the hash table used by the
 * function hostutil_GetNameByINetCached is no longer needed.
 * The hash table will be destroyed only if it is not being used
 * anywhere.
 *
 * @param none
 *
 * @return none
 */
void
hostutil_DestroyHostCache(void)
{
    struct host_cache_entry *bucket;
    afs_uint32 i;

#ifdef AFS_PTHREAD_ENV
    pthread_mutex_lock(&cache_mutex);
#endif
    if (cache == NULL)
	goto done;
    cache_count--;
    if (cache_count > 0)
	goto done;
    for (i = 0; i < HASH_BUCKETS_SIZE; i++) {
	bucket = cache->hash_table[i];
	if (bucket == NULL)
	    continue;
	remove_bucket(bucket);
	cache->hash_table[i] = NULL;
    }
    cache = NULL;
  done:
#ifdef AFS_PTHREAD_ENV
    pthread_mutex_unlock(&cache_mutex);
#endif
    return;
}

/* also parse a.b.c.d addresses */
struct hostent *
hostutil_GetHostByName(char *ahost)
{
    int tc;
    static struct hostent thostent;
    static char *addrp[2];
    static char addr[4];
    char *ptr = ahost;
    afs_uint32 tval, numeric = 0;
    int dots = 0;

    tc = *ahost;		/* look at the first char */
    if (tc >= '0' && tc <= '9') {
	numeric = 1;
	while ((tc = *ptr++)) {
	    if (tc == '.') {
		if (dots >= 3) {
		    numeric = 0;
		    break;
		}
		dots++;
	    } else if (tc > '9' || tc < '0') {
		numeric = 0;
		break;
	    }
	}
    }
    if (numeric) {
	/* decimal address, return fake hostent with only hostaddr field good */
	tval = 0;
	dots = 0;
	memset(addr, 0, sizeof(addr));
	while ((tc = *ahost++)) {
	    if (tc == '.') {
		if (dots >= 3)
		    return NULL;	/* too many dots */
		addr[dots++] = tval;
		tval = 0;
	    } else if (tc > '9' || tc < '0')
		return NULL;
	    else {
		tval *= 10;
		tval += tc - '0';
	    }
	}
	addr[dots] = tval;
#ifdef h_addr
	/* 4.3 system */
	addrp[0] = addr;
	addrp[1] = NULL;
	thostent.h_addr_list = &addrp[0];
#else /* h_addr */
	/* 4.2 and older systems */
	thostent.h_addr = addr;
#endif /* h_addr */
	return &thostent;
    } else {
#ifdef AFS_NT40_ENV
	if (afs_winsockInit() < 0)
	    return NULL;
#endif
	return gethostbyname(ahost);
    }
}

/* Translate an internet address into a nice printable string. The
 * variable addr is in network byte order.
 */
char *
hostutil_GetNameByINet(afs_uint32 addr)
{
    struct sockaddr_in sa;
    static char tbuffer[256];
    int res;

#ifdef AFS_NT40_ENV
    if (afs_winsockInit() < 0)
	return NULL;
#endif
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = addr;
    res =
	getnameinfo((struct sockaddr *)&sa, sizeof(sa), tbuffer,
		    sizeof(tbuffer), NULL, 0, 0);
    if (res)
	return NULL;
    return tbuffer;
}

/**
 * More efficient version of hostutil_GetNameByINet.
 *
 * A hashtable is used to store the result for subsequent lookups.
 *
 * @param[in]  aaddr    ipv4 address in network byte order
 * @param[out] abuffer  host name
 * @param[in]  alen     size of abuffer
 *
 * @return abuffer
 *   @retval host name success
 *   @retval printable ipv4 address not found
 *   @retval abuffer failure
 */
char *
hostutil_GetNameByINetCached(afs_uint32 aaddr, char *abuffer, size_t alen)
{
    struct host_cache_entry *hce;

#ifdef AFS_PTHREAD_ENV
    pthread_mutex_lock(&cache_mutex);
#endif
    hce = find_host_cache(aaddr);
#ifdef AFS_PTHREAD_ENV
    pthread_mutex_unlock(&cache_mutex);
#endif
    if (hce != NULL && strlen(hce->name) < alen) {
	strlcpy(abuffer, hce->name, alen);
    }
    return abuffer;
}

/* the parameter is a pointer to a buffer containing a string of
** bytes of the form
** w.x.y.z 	# machineName
** returns the network interface in network byte order
*/

#define MAXBYTELEN 32
afs_uint32
extractAddr(char *line, int maxSize)
{
    char byte1[MAXBYTELEN], byte2[MAXBYTELEN];
    char byte3[MAXBYTELEN], byte4[MAXBYTELEN];
    int i = 0;
    char *endPtr;
    afs_uint32 val1, val2, val3, val4;
    afs_uint32 val = 0;

    /* skip empty spaces */
    while (isspace(*line) && maxSize) {
	line++;
	maxSize--;
    }

    /* skip empty lines */
    if (!maxSize || !*line)
	return AFS_IPINVALIDIGNORE;

    while ((*line != '.') && maxSize) {	/* extract first byte */
	if (!isdigit(*line))
	    return AFS_IPINVALID;
	if (i >= MAXBYTELEN-1)
	    return AFS_IPINVALID;	/* no space */
	byte1[i++] = *line++;
	maxSize--;
    }
    if (!maxSize)
	return AFS_IPINVALID;
    byte1[i] = 0;

    i = 0, line++;
    while ((*line != '.') && maxSize) {	/* extract second byte */
	if (!isdigit(*line))
	    return AFS_IPINVALID;
	if (i >= MAXBYTELEN-1)
	    return AFS_IPINVALID;	/* no space */
	byte2[i++] = *line++;
	maxSize--;
    }
    if (!maxSize)
	return AFS_IPINVALID;
    byte2[i] = 0;

    i = 0, line++;
    while ((*line != '.') && maxSize) {
	if (!isdigit(*line))
	    return AFS_IPINVALID;
	if (i >= MAXBYTELEN-1)
	    return AFS_IPINVALID;	/* no space */
	byte3[i++] = *line++;
	maxSize--;
    }
    if (!maxSize)
	return AFS_IPINVALID;
    byte3[i] = 0;

    i = 0, line++;
    while (*line && !isspace(*line) && maxSize) {
	if (!isdigit(*line))
	    return AFS_IPINVALID;
	if (i >= MAXBYTELEN-1)
	    return AFS_IPINVALID;	/* no space */
	byte4[i++] = *line++;
	maxSize--;
    }
    if (!maxSize)
	return AFS_IPINVALID;
    byte4[i] = 0;

    errno = 0;
    val1 = strtol(byte1, &endPtr, 10);
    if ((val1 == 0) && (errno != 0 || byte1 == endPtr))
	return AFS_IPINVALID;

    errno = 0;
    val2 = strtol(byte2, &endPtr, 10);
    if ((val2 == 0) && (errno != 0 || byte2 == endPtr))	/* no conversion */
	return AFS_IPINVALID;

    errno = 0;
    val3 = strtol(byte3, &endPtr, 10);
    if ((val3 == 0) && (errno != 0 || byte3 == endPtr))	/* no conversion */
	return AFS_IPINVALID;

    errno = 0;
    val4 = strtol(byte4, &endPtr, 10);
    if ((val4 == 0) && (errno != 0 || byte4 == endPtr))	/* no conversion */
	return AFS_IPINVALID;

    val = (val1 << 24) | (val2 << 16) | (val3 << 8) | val4;
    val = htonl(val);
    return val;
}

/* same as inet_ntoa, but to a non-static buffer, must be freed by called */
char *
afs_inet_ntoa_r(afs_uint32 addr, char *buf)
{
    int temp;

    temp = ntohl(addr);
    sprintf(buf, "%d.%d.%d.%d", (temp >> 24) & 0xff, (temp >> 16) & 0xff,
	    (temp >> 8) & 0xff, (temp) & 0xff);
    return buf;
}

/*
 * gettmpdir() -- Returns pointer to global temporary directory string.
 *     Always succeeds.  Never attempt to deallocate directory string.
 */

char *
gettmpdir(void)
{
    char *tmpdirp = NULL;

#ifdef AFS_NT40_ENV
    static char *saveTmpDir = NULL;

    if (saveTmpDir == NULL) {
	/* initialize global temporary directory string */
	char *dirp = malloc(MAX_PATH+1);
	int freeDirp = 1;

	if (dirp != NULL) {
	    DWORD pathLen = GetTempPath(MAX_PATH+1, dirp);

	    if (pathLen == 0 || pathLen > MAX_PATH) {
		/* can't get tmp path; get cur work dir */
		pathLen = GetCurrentDirectory(MAX_PATH, dirp);
		if (pathLen == 0 || pathLen > MAX_PATH) {
		    free(dirp);
		    dirp = NULL;
		}
	    }

	    if (dirp != NULL) {
		/* Have a valid dir path; check that actually exists. */
		DWORD fileAttr = GetFileAttributes(dirp);

		if ((fileAttr == 0xFFFFFFFF)
		    || ((fileAttr & FILE_ATTRIBUTE_DIRECTORY) == 0)) {
		    free(dirp);
		    dirp = NULL;
		}
	    }
	}

	if (dirp != NULL) {
	    FilepathNormalize(dirp);
	} else {
	    /* most likely TMP or TEMP env vars specify a non-existent dir */
	    dirp = "/";
	    freeDirp = 0;
	}

        /* atomically initialize shared buffer pointer IF still null */
        if (InterlockedCompareExchangePointer(&saveTmpDir, dirp, NULL) != NULL) {
            /* shared buffer pointer already initialized by another thread */
            if (freeDirp)
                free(dirp);
        }
    }
    /* if (!saveTmpDir) */
    tmpdirp = saveTmpDir;
#else
    tmpdirp = "/tmp";
#endif /* AFS_NT40_ENV */

    return tmpdirp;
}

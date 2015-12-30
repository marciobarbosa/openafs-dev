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
#include <afs/opr.h>
#include <opr/dict.h>
#include <opr/jhash.h>
#include <opr/lock.h>

#ifdef AFS_NT40_ENV
#include <direct.h>
#else
#include <ctype.h>
#endif

#include "afsutil.h"

#define HASH_SIZE_LOG2	9		/* 512 buckets */

#define HOSTNAME_TTL	(4*60*60)

#ifdef AFS_PTHREAD_ENV
static opr_mutex_t hostname_cache_mutex;
#define hostNameCacheLock() do { opr_mutex_enter(&hostname_cache_mutex); } while (0)
#define hostNameCacheUnlock() do { opr_mutex_exit(&hostname_cache_mutex); } while (0)
#define hostNameCacheLocked() do { opr_mutex_assert(&hostname_cache_mutex); } while (0)
#else
#define hostNameCacheLock() do { } while (0)
#define hostNameCacheUnlock() do { } while (0)
#define hostNameCacheLocked() do { } while (0)
#endif

static struct opr_dict *hostname_cache = NULL;

struct hostname_cache_entry {
    afs_uint32 address;
    char *hostname;
    time_t expires;
    struct opr_queue link;
};

void
hostutil_InitHostNameCache(void)
{
    if (hostname_cache != NULL)
	return;
    hostname_cache = opr_dict_Init(opr_jhash_size(HASH_SIZE_LOG2));
    if (hostname_cache == NULL) {
	return;
    }
#ifdef AFS_PTHREAD_ENV
    opr_mutex_init(&hostname_cache_mutex);
#endif
}

static void
remove_entry(struct hostname_cache_entry *aentry)
{
    opr_queue_Remove(&aentry->link);
    free(aentry->hostname);
    free(aentry);
}

static struct hostname_cache_entry *
find_hostname(afs_uint32 aaddr)
{
    char *hostname;
    time_t now = time(NULL);
    struct hostname_cache_entry *hce = NULL;
    struct opr_queue *cursor, *store;
    afs_uint32 index = opr_jhash_int((aaddr), 0) & opr_jhash_mask(HASH_SIZE_LOG2); 

    hostNameCacheLocked();
    if (hostname_cache == NULL)
	goto done;

    for (opr_dict_ScanBucketSafe(hostname_cache, index, cursor, store)) {
	hce = opr_queue_Entry(cursor, struct hostname_cache_entry, link);
	if (hce->address == aaddr) {
	    if (hce->expires > now) {
		goto done;
	    } else {
		remove_entry(hce);
		break;
	    }
	}
    }
    hce = (struct hostname_cache_entry *)calloc(1, sizeof(struct hostname_cache_entry));
    if (hce == NULL)
	goto done;
    hce->address = aaddr;
    hostname = hostutil_GetNameByINet(aaddr);
    hce->hostname = strdup(hostname);
    if (hce->hostname == NULL) {
	free(hce);
	hce = NULL;
	goto done;
    }
    hce->expires = time(NULL) + HOSTNAME_TTL;
    opr_dict_Prepend(hostname_cache, index, &hce->link);
  done:
    return hce;
}

char *
hostutil_GetNameByINetCached(afs_uint32 aaddr, char *abuffer, size_t alen)
{
    struct hostname_cache_entry *hce;
    char *hostname;

    hostNameCacheLock();
    hce = find_hostname(aaddr);
    hostNameCacheUnlock();

    if (hce != NULL && strlen(hce->hostname) < alen) {
	strlcpy(abuffer, hce->hostname, alen);
	return abuffer;
    } else if (hce == NULL) {
	hostname = hostutil_GetNameByINet(aaddr);
	if (hostname != NULL && strlen(hostname) < alen) {
	    strlcpy(abuffer, hostname, alen);
	    return abuffer;
	}
    }
    return NULL;
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
    struct hostent *th;
    static char tbuffer[256];

#ifdef AFS_NT40_ENV
    if (afs_winsockInit() < 0)
	return NULL;
#endif
    th = gethostbyaddr((void *)&addr, sizeof(addr), AF_INET);
    if (th && strlen(th->h_name) < sizeof(tbuffer)) {
	strlcpy(tbuffer, th->h_name, sizeof(tbuffer));
    } else {
	addr = ntohl(addr);
	sprintf(tbuffer, "%d.%d.%d.%d", (int)((addr >> 24) & 0xff),
		(int)((addr >> 16) & 0xff), (int)((addr >> 8) & 0xff),
		(int)(addr & 0xff));
    }

    return tbuffer;
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

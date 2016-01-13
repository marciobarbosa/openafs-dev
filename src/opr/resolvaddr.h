#include <opr/dict.h>

#define	HASH_SIZE_LOG2	6	/* 64 buckets */
#define	MAX_SIZE	1024	/* maximum number of entries */
#define DEFAULT_TTL	3600	/* 1 hour */

struct hostname_cache_entry {
    union {
	struct sockaddr sa;
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;
    } address;
    char *hostname;
    time_t expires;
    struct opr_queue link;
};

extern char *opr_resolvaddr(void *addr, size_t addrlen, int af, char *buffer, size_t len);

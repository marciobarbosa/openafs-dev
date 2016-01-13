#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>
#include <tests/tap/basic.h>
#include <opr/resolvaddr.h>

int
main(int argc, char *argv[])
{
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    char buffer[256], *p = NULL;

    if (strcmp(argv[1], "ipv4") == 0) {
	sa4.sin_family = AF_INET;
	inet_pton(AF_INET, argv[2], &sa4.sin_addr);
	p = opr_resolvaddr(&sa4.sin_addr, sizeof(sa4.sin_addr), AF_INET, buffer, 256);
    } else if (strcmp(argv[1], "ipv6") == 0) {
	sa6.sin6_family = AF_INET6;
	inet_pton(AF_INET6, argv[2], &sa6.sin6_addr);
	p = opr_resolvaddr(&sa6.sin6_addr, sizeof(sa6.sin6_addr), AF_INET6, buffer, 256);
    }
    if (p != NULL) {
	printf("Result: %s\n", p);
    } else {
	printf("Something went wrong...\n");
    }
    return 0;
}

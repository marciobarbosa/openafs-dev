/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 * 
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include "afs/param.h"

#ifdef AFS_SOCKPROXY
#include <afs/afs_args.h>
#endif

#include "rx/rx_kcommon.h"
#include "rx/rx_atomic.h"
#include "rx/rx_internal.h"
#include "rx/rx_packet.h"
#include "rx/rx_stats.h"

#ifdef AFS_DARWIN80_ENV
#define soclose sock_close
#endif

#ifdef RXK_UPCALL_ENV

# ifdef AFS_SOCKPROXY

/* osi_socket returned by rxk_NewSocketHost on success */
static socket_t rx_SockProxySocket;

/**
 * Receive packets.
 *
 * @param[in]  addr     source address
 * @param[in]  payload  received data
 *
 * @return none.
 */
void
rx_SockProxyUpCall(int npkts, struct afs_sockproxy_packet *pkts)
{
    struct rx_packet *p;
    struct afs_sockproxy_packet *pkt;
    struct sockaddr_in saddr;
    int host, port;

    int tlen, i;
    int pkt_i;

    char *payloadp;

    pkt = &pkts[0];
    p = NULL;
    /*
     * receiver process calls this function immediately after being forked. the
     * first call does not have any packet.
     */
    if (pkt->nentries == 0) {
	return;
    }

    for (pkt_i = 0; pkt_i < npkts; pkt_i++) {
	pkt = &pkts[pkt_i];
	/* see if a check for additional packets was issued */
	rx_CheckPackets();

	if (p == NULL) {
	    /* alloc and init packet */
	    p = rxi_AllocPacket(RX_PACKET_CLASS_RECEIVE);
	    rx_computelen(p, tlen);
	    rx_SetDataSize(p, tlen);

	    tlen += RX_HEADER_SIZE;
	    tlen = rx_maxJumboRecvSize - tlen;
	    /*
	     * check if our packet is as big as the maximum size of a jumbo datagram we
	     * can receive. if not, try to increase the size of the packet in question.
	     */
	    if (tlen > 0) {
		(void)rxi_AllocDataBuf(p, tlen, RX_PACKET_CLASS_RECV_CBUF);
	    }
	} else {
	    rxi_RestoreDataBufs(p);
	}

	payloadp = (char *)pkt->data;
	for (i = 0; i < pkt->nentries && p->niovecs; i++) {
	    /* assume that iov_base is big enough for now */
	    memcpy(p->wirevec[i].iov_base, payloadp, pkt->len[i]);
	    payloadp += pkt->len[i];
	}

	p->length = pkt->size - RX_HEADER_SIZE;
	/* extract packet header. */
	rxi_DecodePacketHeader(p);

	saddr = pkt->addr;
	host = saddr.sin_addr.s_addr;
	port = saddr.sin_port;
	/* receive pcket */
	p = rxi_ReceivePacket(p, rx_SockProxySocket, host, port, 0, 0);
    }
    if (p) {
	rxi_FreePacket(p);
    }
}

/**
 * Send packets to the given address.
 *
 * @param[in]  so       not used
 * @param[in]  addr     destination address
 * @param[in]  dvec     vector holding data to be sent
 * @param[in]  nvecs    number of dvec entries
 * @param[in]  alength  not used
 * @param[in]  istack   not used
 *
 * @return 0 on success.
 */
int
osi_NetSend(osi_socket so, struct sockaddr_in *addr, struct iovec *dvec,
	    int nvecs, afs_int32 alength, int istack)
{
    int i, code;
    int haveGlock;

    struct sockaddr *sa;
    struct iovec iov[RX_MAXIOVECS];

    AFS_STATCNT(osi_NetSend);

    sa = (struct sockaddr *)addr;
    memset(&iov, 0, sizeof(iov));

    haveGlock = ISAFS_GLOCK();

    if (nvecs > RX_MAXIOVECS) {
	osi_Panic("osi_NetSend: %d: Too many iovecs.\n", nvecs);
    }

    for (i = 0; i < nvecs; i++) {
	iov[i] = dvec[i];
    }
    addr->sin_len = sizeof(struct sockaddr_in);

    if ((afs_termState == AFSOP_STOP_RXK_LISTENER) ||
	(afs_termState == AFSOP_STOP_COMPLETE)) {
	return -1;
    }

    if (haveGlock) {
	AFS_GUNLOCK();
    }

    /* returns the number of bytes sent */
    code = rx_SockProxyRequest(SOCKPROXY_SEND, sa, iov, nvecs);
    if (code >= 0) {
	/* success */
	code = 0;
    }

    if (haveGlock) {
	AFS_GLOCK();
    }
    return code;
}

/**
 * Cancel rx listener and socket proxy.
 *
 * @return none.
 */
void
osi_StopNetIfPoller(void)
{
    /* not working yet */
    AFS_GUNLOCK();
    rx_SockProxyRequest(SOCKPROXY_CLOSE, NULL, NULL, 0);
    rx_SockProxyRequest(SOCKPROXY_SHUTDOWN, NULL, NULL, 0);
    AFS_GLOCK();
}

/**
 * Open and bind RX socket.
 *
 * @param[in]  ahost  ip address
 * @param[in]  aport  port number
 *
 * @return non-NULL on success; NULL otherwise.
 */
osi_socket *
rxk_NewSocketHost(afs_uint32 ahost, short aport)
{
    int code;
    osi_socket *ret;

    struct sockaddr *sa;
    struct sockaddr_in addr;

    ret = NULL;
    sa = (struct sockaddr *)&addr;
    memset(&addr, 0, sizeof(addr));

    AFS_STATCNT(osi_NewSocket);
    AFS_ASSERT_GLOCK();
    AFS_GUNLOCK();
    /* create socket */
    code = rx_SockProxyRequest(SOCKPROXY_SOCKET, NULL, NULL, 0);
    if (code < 0) {
	goto done;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = aport;
    addr.sin_addr.s_addr = ahost;
    /* set options */
    code = rx_SockProxyRequest(SOCKPROXY_SETOPT, NULL, NULL, 0);
    if (code != 0) {
	/* preserving original behavior */
	osi_Panic("osi_NewSocket: last attempt to reserve 32K failed!\n");
    }
    /* assign addr to the socket */
    code = rx_SockProxyRequest(SOCKPROXY_BIND, sa, NULL, 0);
    if (code != 0) {
	printf("sobind fails (%d)\n", code);
	rx_SockProxyRequest(SOCKPROXY_CLOSE, NULL, NULL, 0);
	goto done;
    }
    /*
     * success. notice that the rxk_NewSocketHost interface forces us to return
     * an osi_socket address on success. however, if AFS_SOCKPROXY is defined,
     * the socket returned by this function is not used. since the caller is
     * expecting an osi_socket, return one to represent success.
     */
    rx_SockProxySocket = rxi_Alloc(sizeof(socket_t));
    ret = (osi_socket *)rx_SockProxySocket;
  done:
    AFS_GLOCK();
    return ret;
}

/**
 * Open and bind RX socket to all local interfaces.
 *
 * @param[in]  aport  port number
 *
 * @return non-NULL on success; NULL otherwise.
 */
osi_socket *
rxk_NewSocket(short aport)
{
    return rxk_NewSocketHost(0, aport);
}

/**
 * Close socket opened by rxk_NewSocket.
 *
 * @param[in]  asocket  not used
 *
 * @return 0 on success.
 */
int
rxk_FreeSocket(struct socket *asocket)
{
    int code;

    AFS_STATCNT(osi_FreeSocket);
    code = rx_SockProxyRequest(SOCKPROXY_CLOSE, NULL, NULL, 0);

    return code;
}

# else

void
rx_upcall(socket_t so, void *arg, __unused int waitflag)
{
    mbuf_t m;
    int error = 0;
    int i, flags = 0;
    struct msghdr msg;
    struct sockaddr_storage ss;
    struct sockaddr *sa = NULL;
    struct sockaddr_in from;
    struct rx_packet *p;
    afs_int32 rlen;
    afs_int32 tlen;
    afs_int32 savelen;          /* was using rlen but had aliasing problems */
    size_t nbytes, resid, noffset;

    /* we stopped rx but the socket isn't closed yet */
    if (!rxi_IsRunning())
	return;

    /* See if a check for additional packets was issued */
    rx_CheckPackets();

    p = rxi_AllocPacket(RX_PACKET_CLASS_RECEIVE);
    rx_computelen(p, tlen);
    rx_SetDataSize(p, tlen);    /* this is the size of the user data area */
    tlen += RX_HEADER_SIZE;     /* now this is the size of the entire packet */
    rlen = rx_maxJumboRecvSize; /* this is what I am advertising.  Only check
				 * it once in order to avoid races.  */
    tlen = rlen - tlen;
    if (tlen > 0) {
	tlen = rxi_AllocDataBuf(p, tlen, RX_PACKET_CLASS_RECV_CBUF);
	if (tlen > 0) {
	    tlen = rlen - tlen;
	} else
	    tlen = rlen;
    } else
	tlen = rlen;
    /* add some padding to the last iovec, it's just to make sure that the
     * read doesn't return more data than we expect, and is done to get around
     * our problems caused by the lack of a length field in the rx header. */
    savelen = p->wirevec[p->niovecs - 1].iov_len;
    p->wirevec[p->niovecs - 1].iov_len = savelen + RX_EXTRABUFFERSIZE;

    resid = nbytes = tlen + sizeof(afs_int32);

    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = &ss;
    msg.msg_namelen = sizeof(struct sockaddr_storage);
    sa =(struct sockaddr *) &ss;

    do {
	m = NULL;
	error = sock_receivembuf(so, &msg, &m, MSG_DONTWAIT, &nbytes);
	if (!error) {
	    size_t sz, offset = 0;
	    noffset = 0;
	    resid = nbytes;
	    for (i=0;i<p->niovecs && resid;i++) {
		sz=MIN(resid, p->wirevec[i].iov_len);
		error = mbuf_copydata(m, offset, sz, p->wirevec[i].iov_base);
		if (error)
		    break;
		resid-=sz;
		offset+=sz;
		noffset += sz;
	    }
	}
    } while (0);

    mbuf_freem(m);

    /* restore the vec to its correct state */
    p->wirevec[p->niovecs - 1].iov_len = savelen;

    if (error == EWOULDBLOCK && noffset > 0)
	error = 0;

    if (!error) {
	int host, port;

	nbytes -= resid;

	if (sa->sa_family == AF_INET)
	    from = *(struct sockaddr_in *)sa;

	p->length = nbytes - RX_HEADER_SIZE;;
	if ((nbytes > tlen) || (p->length & 0x8000)) {  /* Bogus packet */
	    if (nbytes <= 0) {
		if (rx_stats_active) {
		    MUTEX_ENTER(&rx_stats_mutex);
		    rx_atomic_inc(&rx_stats.bogusPacketOnRead);
		    rx_stats.bogusHost = from.sin_addr.s_addr;
		    MUTEX_EXIT(&rx_stats_mutex);
		}
		dpf(("B: bogus packet from [%x,%d] nb=%d",
		     from.sin_addr.s_addr, from.sin_port, nbytes));
	    }
	    return;
	} else {
	    /* Extract packet header. */
	    rxi_DecodePacketHeader(p);

	    host = from.sin_addr.s_addr;
	    port = from.sin_port;
	    if (p->header.type > 0 && p->header.type < RX_N_PACKET_TYPES) {
		if (rx_stats_active) {
		    rx_atomic_inc(&rx_stats.packetsRead[p->header.type - 1]);
		}
	    }

#ifdef RX_TRIMDATABUFS
	    /* Free any empty packet buffers at the end of this packet */
	    rxi_TrimDataBufs(p, 1);
#endif
	    /* receive pcket */
	    p = rxi_ReceivePacket(p, so, host, port, 0, 0);
	}
    }
    /* free packet? */
    if (p)
	rxi_FreePacket(p);

    return;
}

/* in listener env, the listener shutdown does this. we have no listener */
void
osi_StopNetIfPoller(void)
{
    soclose(rx_socket);
    if (afs_termState == AFSOP_STOP_NETIF) {
	afs_termState = AFSOP_STOP_COMPLETE;
	osi_rxWakeup(&afs_termState);
    }
}

# endif	/* AFS_SOCKPROXY */

#elif defined(RXK_LISTENER_ENV)

int
osi_NetReceive(osi_socket so, struct sockaddr_in *addr, struct iovec *dvec,
	       int nvecs, int *alength)
{
    int i;
    struct iovec iov[RX_MAXIOVECS];
    struct sockaddr *sa = NULL;
    int code;
    size_t resid;

    int haveGlock = ISAFS_GLOCK();

#ifdef AFS_DARWIN80_ENV
    socket_t asocket = (socket_t)so;
    struct msghdr msg;
    struct sockaddr_storage ss;
    int rlen;
    mbuf_t m;
#else
    struct socket *asocket = (struct socket *)so;
    struct uio u;
    memset(&u, 0, sizeof(u));
#endif
    memset(&iov, 0, sizeof(iov));
    /*AFS_STATCNT(osi_NetReceive); */

    if (nvecs > RX_MAXIOVECS)
	osi_Panic("osi_NetReceive: %d: Too many iovecs.\n", nvecs);

    for (i = 0; i < nvecs; i++)
	iov[i] = dvec[i];

    if ((afs_termState == AFSOP_STOP_RXK_LISTENER) ||
	(afs_termState == AFSOP_STOP_COMPLETE))
	return -1;

    if (haveGlock)
	AFS_GUNLOCK();
#if defined(KERNEL_FUNNEL)
    thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
#endif
#ifdef AFS_DARWIN80_ENV
    resid = *alength;
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = &ss;
    msg.msg_namelen = sizeof(struct sockaddr_storage);
    sa =(struct sockaddr *) &ss;
    code = sock_receivembuf(asocket, &msg, &m, 0, alength);
    if (!code) {
        size_t offset=0,sz;
        resid = *alength;
        for (i=0;i<nvecs && resid;i++) {
            sz=MIN(resid, iov[i].iov_len);
            code = mbuf_copydata(m, offset, sz, iov[i].iov_base);
            if (code)
                break;
            resid-=sz;
            offset+=sz;
        }
    }
    mbuf_freem(m);
#else

    u.uio_iov = &iov[0];
    u.uio_iovcnt = nvecs;
    u.uio_offset = 0;
    u.uio_resid = *alength;
    u.uio_segflg = UIO_SYSSPACE;
    u.uio_rw = UIO_READ;
    u.uio_procp = NULL;
    code = soreceive(asocket, &sa, &u, NULL, NULL, NULL);
    resid = u.uio_resid;
#endif

#if defined(KERNEL_FUNNEL)
    thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
#endif
    if (haveGlock)
	AFS_GLOCK();

    if (code)
	return code;
    *alength -= resid;
    if (sa) {
	if (sa->sa_family == AF_INET) {
	    if (addr)
		*addr = *(struct sockaddr_in *)sa;
	} else
	    printf("Unknown socket family %d in NetReceive\n", sa->sa_family);
#ifndef AFS_DARWIN80_ENV
	FREE(sa, M_SONAME);
#endif
    }
    return code;
}

extern int rxk_ListenerPid;
void
osi_StopListener(void)
{
    struct proc *p;

#if defined(KERNEL_FUNNEL)
    thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
#endif
    soclose(rx_socket);
#if defined(KERNEL_FUNNEL)
    thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
#endif
#ifndef AFS_DARWIN80_ENV
    p = pfind(rxk_ListenerPid);
    if (p)
	psignal(p, SIGUSR1);
#endif
}

int
osi_NetSend(osi_socket so, struct sockaddr_in *addr, struct iovec *dvec,
	    int nvecs, afs_int32 alength, int istack)
{
    afs_int32 code;
    int i;
    struct iovec iov[RX_MAXIOVECS];
    int haveGlock = ISAFS_GLOCK();
#ifdef AFS_DARWIN80_ENV
    socket_t asocket = (socket_t)so;
    struct msghdr msg;
    size_t slen;
#else
    struct socket *asocket = (struct socket *)so;
    struct uio u;
    memset(&u, 0, sizeof(u));
#endif
    memset(&iov, 0, sizeof(iov));

    AFS_STATCNT(osi_NetSend);
    if (nvecs > RX_MAXIOVECS)
	osi_Panic("osi_NetSend: %d: Too many iovecs.\n", nvecs);

    for (i = 0; i < nvecs; i++)
	iov[i] = dvec[i];

    addr->sin_len = sizeof(struct sockaddr_in);

    if ((afs_termState == AFSOP_STOP_RXK_LISTENER) ||
	(afs_termState == AFSOP_STOP_COMPLETE))
	return -1;

    if (haveGlock)
	AFS_GUNLOCK();

#if defined(KERNEL_FUNNEL)
    thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
#endif
#ifdef AFS_DARWIN80_ENV
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = addr;
    msg.msg_namelen = ((struct sockaddr *)addr)->sa_len;
    msg.msg_iov = &iov[0];
    msg.msg_iovlen = nvecs;
    code = sock_send(asocket, &msg, 0, &slen);
#else
    u.uio_iov = &iov[0];
    u.uio_iovcnt = nvecs;
    u.uio_offset = 0;
    u.uio_resid = alength;
    u.uio_segflg = UIO_SYSSPACE;
    u.uio_rw = UIO_WRITE;
    u.uio_procp = NULL;
    code = sosend(asocket, (struct sockaddr *)addr, &u, NULL, NULL, 0);
#endif

#if defined(KERNEL_FUNNEL)
    thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
#endif
    if (haveGlock)
	AFS_GLOCK();
    return code;
}

#else
#error need upcall or listener
#endif

#ifndef NETINET_IP6_H
#define NETINET_IP6_H

#include <ws2tcpip.h>
#include <stdint.h>

// IP6 Header Structure
typedef struct ip6_hdr
{
    union
    {
        struct ip6_hdrctl
        {
            uint32_t ip6_un1_flow;   /* 24 bits of flow-ID */
            uint16_t ip6_un1_plen;   /* payload length */
            uint8_t  ip6_un1_nxt;    /* next header */
            uint8_t  ip6_un1_hlim;   /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc;     /* 4 bits version, 4 bits priority */
    } ip6_ctlun;
    struct in6_addr ip6_src;     /* source address */
    struct in6_addr ip6_dst;     /* destination address */
} IP6_HDR, *PIP6_HDR;

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

typedef struct ip6ph_hdr
{
    struct in6_addr ip6ph_src;
    struct in6_addr ip6ph_dst;
    uint32_t        ip6ph_len;
    uint8_t         ip6ph_zero[3];
    uint8_t         ip6ph_nxt;
} IP6PH_HDR, *PIP6PH_HDR;

#define IP6_HDRLEN sizeof( IP6_HDR )

#endif

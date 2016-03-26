#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>

#include "pcaps.h"
#include "getaddrs.h" // ntop() / pton() in case API doesn't have it ... like mine
#include "hexString.h"

#include "netinet/if_ether.h"
#include "netinet/ip.h"
#include "netinet/ip6.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "netinet/icmp6.h"

int checkPacketNotLen( int slen, int len )
{
    if ( slen < len )
    {
        fprintf( stderr,
             "Packet not long enough (%i) - `%i'\n", len, slen );
/*
        if ( !cCont )
            exit(1);
*/
        return 1;
    }
    return 0;
}

void rewriteMac( char* argv, int len, char* mac )
{
    PETH_HDR ether;

    ether = (PETH_HDR)argv;
    memcpy( ether->ether_shost, hexStringToBytes( mac ), ETHER_ADDR_LEN );
}

void rewriteMacGw( char* argv, int len, char* mac_gw )
{
    PETH_HDR ether;

    ether = (PETH_HDR)argv;
    memcpy( ether->ether_dhost, hexStringToBytes( mac_gw ), ETHER_ADDR_LEN );
}

void rewriteIpv4( char* argv, int len, char* ipv4 )
{
    PETH_HDR ether;
    PIP_HDR  ip;

    PTCP_HDR   tcp;
    PUDP_HDR   udp;
    int ulen;

    ether = (PETH_HDR)argv;

    // IPv4
    if ( ntohs( ether->ether_type ) == ETHER_TYPE_IP )
    {
#ifdef DEBUG
        printf("rewrite.c - IPv4 rewrite\n");
#endif
        if ( checkPacketNotLen( len, ( ETHER_HDRLEN + IP_HDRLEN ) ) )
            return;
        ip = (PIP_HDR)(argv + ETHER_HDRLEN);
        inet_pton( AF_INET, ipv4, &(ip->ip_saddr) );
        ip->ip_checksum = 0;
        ip->ip_checksum = ip_checksum( ip, ( ip->ip_ihl * 4 ) );
#ifdef DEBUG
        printf("rewrite.c - IPv4 checksum recalculated = %x\n", ntohs( ip->ip_checksum ) );
#endif

        // TCP checksum
        if ( ip->ip_protocol == IPPROTO_TCP )
        {
            ulen = len - ETHER_HDRLEN - ( ip->ip_ihl * 4 );

            if ( checkPacketNotLen( len, ( ETHER_HDRLEN + ( ip->ip_ihl * 4 ) + TCP_HDRLEN ) ) )
                return;

            tcp = (PTCP_HDR)(argv + ETHER_HDRLEN + ( ip->ip_ihl * 4 ) );
            tcp->tcp_checksum = 0;
            tcp->tcp_checksum = tcp_checksum( tcp, ulen, ip->ip_saddr, ip->ip_daddr );
#ifdef DEBUG
            printf("rewrite.c - TCPv4 checksum recalculated = %x\n", ntohs( tcp->tcp_checksum ) );
#endif
        }

        // UDP checksum
        if ( ip->ip_protocol == IPPROTO_UDP )
        {
            if ( checkPacketNotLen( len, ( ETHER_HDRLEN + ( ip->ip_ihl * 4 ) + UDP_HDRLEN ) ) )
                return;

            ulen = len - ETHER_HDRLEN - ( ip->ip_ihl * 4 );
            udp = (PUDP_HDR)(argv + ETHER_HDRLEN + ( ip->ip_ihl * 4 ) );
            udp->udp_checksum = 0;
            udp->udp_checksum = udp_checksum( udp, ulen, ip->ip_saddr, ip->ip_daddr );
#ifdef DEBUG
            printf("rewrite.c - UDPv4 checksum recalculated = %x\n", ntohs( udp->udp_checksum ) );
#endif
        }
    }
}

void rewriteIpv6( char* argv, int len, char* ipv6 )
{
    PETH_HDR ether;
    PIP6_HDR ip6;

    PTCP_HDR   tcp;
    PUDP_HDR   udp;
    PICMP6_HDR icmp6;
    int ulen;

    ether = (PETH_HDR)argv;

    // IPv6
    if ( ntohs( ether->ether_type ) == ETHER_TYPE_IP6 )
    {
#ifdef DEBUG
        printf("rewrite.c - IPv6 rewrite\n");
#endif
        if ( checkPacketNotLen( len, ( ETHER_HDRLEN + IP6_HDRLEN ) ) )
            return;
        ip6 = (PIP6_HDR)(argv + ETHER_HDRLEN);
        inet_pton( AF_INET6, ipv6, &(ip6->ip6_src) );

        // TCP checksum
        if ( ip6->ip6_nxt == IPPROTO_TCP )
        {
            ulen = len - ETHER_HDRLEN - IP6_HDRLEN;

            if ( checkPacketNotLen( len, ( ETHER_HDRLEN + IP6_HDRLEN + TCP_HDRLEN ) ) )
                return;

            tcp = (PTCP_HDR)(argv + ETHER_HDRLEN + IP6_HDRLEN );
            tcp->tcp_checksum = 0;
            tcp->tcp_checksum = tcp6_checksum( tcp, ulen, ip6->ip6_src, ip6->ip6_dst );
#ifdef DEBUG
            printf("rewrite.c - TCPv6 checksum recalculated = %x\n", ntohs( tcp->tcp_checksum ) );
#endif
        }

        // UDP checksum
        if ( ip6->ip6_nxt == IPPROTO_UDP )
        {
            ulen = len - ETHER_HDRLEN - IP6_HDRLEN;

            if ( checkPacketNotLen( len, ( ETHER_HDRLEN + IP6_HDRLEN + UDP_HDRLEN ) ) )
                return;

            udp = (PUDP_HDR)(argv + ETHER_HDRLEN + IP6_HDRLEN );
            udp->udp_checksum = 0;
            udp->udp_checksum = udp6_checksum( udp, ulen, ip6->ip6_src, ip6->ip6_dst );
#ifdef DEBUG
            printf("rewrite.c - UDPv6 checksum recalculated = %x\n", ntohs( udp->udp_checksum ) );
#endif
        }

        // ICMPv6 checksum
        if ( ip6->ip6_nxt == IPPROTO_ICMPV6 )
        {
            ulen = len - ETHER_HDRLEN - IP6_HDRLEN;

            if ( checkPacketNotLen( len, ( ETHER_HDRLEN + IP6_HDRLEN + ICMP6_HDRLEN ) ) )
                return;

            icmp6 = (PICMP6_HDR)(argv + ETHER_HDRLEN + IP6_HDRLEN );
            icmp6->icmp6_checksum = 0;
            icmp6->icmp6_checksum = icmp6_checksum( icmp6, ulen, ip6->ip6_src, ip6->ip6_dst );
#ifdef DEBUG
            printf("rewrite.c - ICMPv6 checksum recalculated = %x\n", ntohs( icmp6->icmp6_checksum ) );
#endif
        }
    }
}

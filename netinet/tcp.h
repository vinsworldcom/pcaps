#ifndef NETINET_TCP_H
#define NETINET_TCP_H

#include <ws2tcpip.h>
#include <stdint.h>

// Explicit Congestion Notification (ECN) Flags - RFC 3168
#define CWR 0x80
#define ECE 0x40

// Standard TCP flags
#define URG 0x20
#define ACK 0x10
#define PSH 0x08
#define RST 0x04
#define SYN 0x02
#define FIN 0x01

// TCP Header Structure
typedef struct tcp_hdr
{
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t  tcp_x2:4,
             tcp_off:4;
    uint8_t  tcp_flags;
    uint16_t tcp_win;
    uint16_t tcp_checksum;
    uint16_t tcp_urp;
} TCP_HDR, *PTCP_HDR;

#define TCP_HDRLEN sizeof( TCP_HDR )

uint16_t tcp_checksum(const void *buff, size_t len, uint32_t src_addr, uint32_t dest_addr)
{
    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
    uint32_t sum;
    size_t length=len;
 
    // Calculate the sum
    sum = 0;
    while (len > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }
 
    if ( len & 1 )
        // Add the padding if the packet length is odd
        sum += *((uint8_t *)buf);
 
    // Add the pseudo-header
    sum += *(ip_src++);
    sum += *ip_src;
    sum += *(ip_dst++);
    sum += *ip_dst;
    sum += htons(IPPROTO_TCP);
    sum += htons(length);
 
    // Add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
 
    // Return the one's complement of sum
    return ( (uint16_t)(~sum)  );
}

uint16_t tcp6_checksum(const void *buff, size_t len, struct in6_addr src_addr, struct in6_addr dest_addr)
{
    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
    uint32_t sum;
    size_t length=len;
 
    // Calculate the sum
    sum = 0;
    while (len > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }
 
    if ( len & 1 )
        // Add the padding if the packet length is odd
        sum += *((uint8_t *)buf);
 
    // Add the pseudo-header
    sum += *(ip_src+7);
    sum += *(ip_src+6);
    sum += *(ip_src+5);
    sum += *(ip_src+4);
    sum += *(ip_src+3);
    sum += *(ip_src+2);
    sum += *(ip_src+1);
    sum += *ip_src;
    sum += *(ip_dst+7);
    sum += *(ip_dst+6);
    sum += *(ip_dst+5);
    sum += *(ip_dst+4);
    sum += *(ip_dst+3);
    sum += *(ip_dst+2);
    sum += *(ip_dst+1);
    sum += *ip_dst;
    sum += htons(length);
    sum += htons(IPPROTO_TCP);
 
    // Add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
 
    // Return the one's complement of sum
    return ( (uint16_t)(~sum)  );
}

#endif

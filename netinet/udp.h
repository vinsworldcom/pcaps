#ifndef NETINET_UDP_H
#define NETINET_UDP_H

#include <ws2tcpip.h>
#include <stdint.h>

// UDP Header Structure
typedef struct udp_hdr
{
    uint16_t udp_sport;
    uint16_t udp_dport;
    uint16_t udp_len;
    uint16_t udp_checksum;
} UDP_HDR, *PUDP_HDR;

#define UDP_HDRLEN sizeof( UDP_HDR )

uint16_t udp_checksum(const void *buff, size_t len, uint32_t src_addr, uint32_t dest_addr)
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
    sum += htons(IPPROTO_UDP);
    sum += htons(length);
 
    // Add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
 
    // Return the one's complement of sum
    return ( (uint16_t)(~sum)  );
}

uint16_t udp6_checksum(const void *buff, size_t len, struct in6_addr src_addr, struct in6_addr dest_addr)
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
    sum += htons(IPPROTO_UDP);
 
    // Add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
 
    // Return the one's complement of sum
    return ( (uint16_t)(~sum)  );
}

#endif

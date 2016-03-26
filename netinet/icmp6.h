#ifndef NETINET_ICMP6_H
#define NETINET_ICMP6_H

#include <ws2tcpip.h>
#include <stdint.h>

typedef struct icmp6_hdr
{
    uint8_t  icmp6_type;      /* type field */
    uint8_t  icmp6_code;      /* code field */
    uint16_t icmp6_checksum;  /* checksum field */
    union
    {
        uint32_t icmp6_un_data32[1]; /* type-specific field */
        uint16_t icmp6_un_data16[2]; /* type-specific field */
        uint8_t  icmp6_un_data8[4];  /* type-specific field */
    } icmp6_dataun;
} ICMP6_HDR, *PICMP6_HDR;

#define ICMP6_HDRLEN sizeof( ICMP6_HDR )

#define icmp6_data32   icmp6_dataun.icmp6_un_data32
#define icmp6_data16   icmp6_dataun.icmp6_un_data16
#define icmp6_data8    icmp6_dataun.icmp6_un_data8
#define icmp6_pptr     icmp6_data32[0]     /* parameter prob */
#define icmp6_mtu      icmp6_data32[0]     /* packet too big */
#define icmp6_id       icmp6_data16[0]     /* echo request/reply */
#define icmp6_seq      icmp6_data16[1]     /* echo request/reply */
#define icmp6_maxdelay icmp6_data16[0]     /* mcast group membership */

uint16_t icmp6_checksum(const void *buff, size_t len, struct in6_addr src_addr, struct in6_addr dest_addr)
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
    sum += htons(IPPROTO_ICMPV6);
 
    // Add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
 
    // Return the one's complement of sum
    return ( (uint16_t)(~sum)  );
}

#endif

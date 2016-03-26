#ifndef NETINET_IP_H
#define NETINET_IP_H

#include <ws2tcpip.h>
#include <stdint.h>

// IP Fragmentation flags
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000

// IP Header Structure
typedef struct ip_hdr
{
    uint8_t  ip_ihl:4,      // Internet header length (network order / big-endian)
             ip_version:4;  // IP version  (network order / big-endian)
    uint8_t  ip_tos;        // IP type of service
    uint16_t ip_len;        // Total length
    uint16_t ip_id;         // Unique identifier
    uint16_t ip_offset;     // Fragment offset field
    uint8_t  ip_ttl;        // Time to live
    uint8_t  ip_protocol;   // Protocol(TCP, UDP, etc.)
    uint16_t ip_checksum;   // IP checksum
    uint32_t ip_saddr;      // Source address
    uint32_t ip_daddr;      // Destination address
} IP_HDR, *PIP_HDR;

#define IP_HDRLEN sizeof( IP_HDR )

// Pseudo Header Structure
typedef struct ipph_hdr
{
    uint32_t ipph_saddr;
    uint32_t ipph_daddr;
    uint8_t  ipph_zero;
    uint8_t  ipph_protocol;
    uint16_t ipph_len;
} IPPH_HDR, *PIPPH_HDR;

uint16_t ip_checksum( const void *buf, size_t hdr_len )
{
    unsigned long sum = 0;
    const uint16_t *ip1;
    ip1 = buf;
    while (hdr_len > 1)
    {
        sum += *ip1++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        hdr_len -= 2;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
 
    return(~sum);
}

#endif

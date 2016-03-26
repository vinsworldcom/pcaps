#ifndef NETINET_IF_ETHER_H
#define NETINET_IF_ETHER_H

#include <stdint.h>

#define ETHERMTU 1500

// The number of bytes in an Ethernet (MAC) address.
#define ETHER_ADDR_LEN 6

#define ETHER_TYPE_IP   0x0800
#define ETHER_TYPE_ARP  0x0806
#define ETHER_TYPE_IP6  0x86DD

// Structure of a DEC/Intel/Xerox or 802.3 Ethernet header.
typedef struct ether_header
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN];
    uint8_t  ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
} ETH_HDR, *PETH_HDR;

/*
 * Length of a DEC/Intel/Xerox or 802.3 Ethernet header; note that some
 * compilers may pad "struct ether_header" to a multiple of 4 bytes,
 * for example, so "sizeof (struct ether_header)" may not give the right
 * answer.
 */
#define ETHER_HDRLEN 14

#endif

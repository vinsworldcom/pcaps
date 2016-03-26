#ifndef GETADDRS_H
#define GETADDRS_H

typedef struct getaddrs {
    char mac[13];      // +1 for \0
    char mac_gw[13];   // +1 for \0
    char ipv4[16];     // +1 for \0
    char ipv4_gw[16];  // +1 for \0
    char ipv6[40];     // +1 for \0
    char ipv6_gw[40];  // +1 for \0
    char error;
} GETADDRS, *PGETADDRS;

GETADDRS getaddrs( char * );

#ifndef InetNtopA
WINSOCK_API_LINKAGE PCSTR WSAAPI inet_ntop(INT, PVOID, PSTR, size_t);
#define InetNtopA inet_ntop
#endif

#ifndef InetPtonA
WINSOCK_API_LINKAGE INT WSAAPI inet_pton(INT, PCSTR, PVOID);
#define InetPtonA inet_pton
#endif

#endif /*GETADDRS_H*/

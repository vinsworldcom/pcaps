#define HAVE_REMOTE

#include <pcap.h>

#include "getaddrs.h"
#include "hexString.h"
#include "pcaps.h"
#include "rewrite.h"

#include "netinet/if_ether.h"

int pcapsend( PGETADDRS addrs, uint8_t flags, char *dev, char *pUserInput, int len )
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Open the output device */
    if ( ( fp = pcap_open_live( dev, // name of the device
                                100,                             // portion of the packet to capture (only the first 100 bytes)
                                PCAP_OPENFLAG_PROMISCUOUS,       // promiscuous mode
                                1000,               // read timeout
                                errbuf              // error buffer
                              ) ) == NULL )
    {
        fprintf( stderr, "Unable to open adapter - `%s'\n", dev );
        exit(1);
    }

    // At least as long as complete Ethernet frame
    if ( checkPacketNotLen( len, ETHER_HDRLEN ) )
        return 0;

    if ( flags&RW_MAC )
        rewriteMac( pUserInput, len, addrs->mac );
    if ( flags&RW_MGW )
        rewriteMacGw( pUserInput, len, addrs->mac_gw );
    if ( flags&RW_IP4 )
        rewriteIpv4( pUserInput, len, addrs->ipv4 );
    if ( flags&RW_IP6 )
        rewriteIpv6( pUserInput, len, addrs->ipv6 );

    if ( flags&VERBOSE )
        printf("Packet       = %s\n", bytesToHexString( (uint8_t *)pUserInput, len*2 ));

    /* Send the packet */
    if ( pcap_sendpacket( fp, ( u_char *)pUserInput, len /* size */ ) != 0 )
        fprintf( stderr, "Error sending packet: %s\n", pcap_geterr( fp ) );

    return 1;
}

#define HAVE_REMOTE

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "pcaps_private.h"
#include <pcap.h>

#include "pcaps.h"
#include "dgets.h"
#include "hexString.h"
#ifdef ADDRS
#include "getaddrs.h"
#include "rewrite.h"
#endif

//char cCont = 0;
char cVerbose = 0;
#ifdef ADDRS
char cIpv4 = 0;
char cIpv6 = 0;
char cGw   = 0;
char cMac  = 0;
#endif

/* Prototypes */
void usage( void );
void help( void );
void version( void );
void printDevs( void );
#ifdef ADDRS
int pcaps( FILE *, PGETADDRS, char *, char * );
#else
int pcaps( FILE *, char *, char * );
#endif

int main( int argc, char *argv[] )
{
    /* variables */
    program_name = argv[0];
    FILE *fd;
#ifdef ADDRS
    GETADDRS addrs;
#endif

    /* START: command line options variables */
    char arglist[10] = "DV"; //c
    static int show_help    = 0;
    static int show_version = 0;
    int ret, opt_index;
    struct option cloptions[] =
    {
        {"devices"    , no_argument       , NULL,         'D'},
//        {"continue"   , no_argument       , NULL,         'c'},
        {"verbose"    , no_argument       , NULL,         'V'},
#ifdef ADDRS
        {"ipv4"       , no_argument       , NULL,         'i'},
        {"ipv6"       , no_argument       , NULL,         'I'},
        {"gatewaymac" , no_argument       , NULL,         'g'},
        {"mac"        , no_argument       , NULL,         'm'},
#endif
        {"help"     , no_argument       , &show_help,    1 },
        {"version"  , no_argument       , &show_version, 1 },
        {0, 0, 0, 0}
    };
    /* END: command line options variables */

#ifdef ADDRS
    strcat (arglist, "iIgm");
#endif

    /* parse command line options */
    while ( ( ret = getopt_long( argc, argv, arglist, cloptions, &opt_index ) ) != -1 )
    {
        switch ( ret )
        {
            case 'D':
                printDevs();

/*
                case 'c':
                cCont = 1;
                break;
*/

                case 'V':
                cVerbose = 1;
                break;
#ifdef ADDRS
                case 'i':
                cIpv4 = 1;
                break;

                case 'I':
                cIpv6 = 1;
                break;

                case 'g':
                cGw = 1;
                break;

                case 'm':
                cMac = 1;
                break;
#endif
                case '?':
                usage();
            default:
                break;
        }
    }

    if ( show_help ) help();
    if ( show_version ) version();

    argc -= optind;
    argv += optind;

#ifdef ADDRS
    if ( ( argc >= 1 ) && ( cGw || cMac || cIpv4 || cIpv6 ) )
    {
        addrs = getaddrs( argv[0] );
        if ( addrs.error )
            return 1;
        if ( cVerbose )
        {
            printf("MAC Address  = %s\n", addrs.mac);
            printf("MAC Gateway  = %s\n", addrs.mac_gw);
            printf("IPv4 Address = %s\n", addrs.ipv4);
            printf("IPv4 Gateway = %s\n", addrs.ipv4_gw);
            printf("IPv6 Address = %s\n", addrs.ipv6);
            printf("IPv6 Gateway = %s\n", addrs.ipv6_gw);
        }
    }
#endif

    /* no input - get from STDIN */
    if (argc == 1)
    {
        fd = stdin;
#ifdef ADDRS
        pcaps(fd, &addrs, argv[0], 0);
#else
        pcaps(fd, argv[0], 0);
#endif
    }
    else if (argc > 1)
    {
        /* loop on remaining argv */
        fd = 0;
        int i;
        for (i = 1; i < argc; i++)
#ifdef ADDRS
            pcaps(fd, &addrs, argv[0], argv[i]);
#else
            pcaps(fd, argv[0], argv[i]);
#endif
    }
    else
        usage();

    return(0);
}

void help( void )
{
    printf( "\
Usage: %s [OPTION] if [packet]\n\
\n\
%s\n\
\n\
  if                     Interface to send on.\n\
  packet                 Packet to send in hex string format.\n\
  -D, --devices          List devices and exit.\n",
    program_name, FILE_DESCRIPTION );
#ifdef ADDRS
    printf("\
  -i, --ipv4             Overwrite source IPv4 with station IPv4\n\
                           found on interface.\n\
  -I, --ipv6             Overwrite source IPv6 with station IPv6\n\
                           found on interface.\n\
                         NOTE: rewriting IPv4/v6 addresses will\n\
                           attempt to recalculate checksums in IPv4\n\
                           and upper layers.\n");
#endif
/*
    printf("\
  -c, --continue         Try to continue on some errors instead\n\
                           of exit.\n");
*/
#ifdef ADDRS
    printf("\
  -g, --gatewaymac       Overwrite destination MAC with gateway MAC\n\
                           found from ARP on interface.\n\
  -m, --mac              Overwrite source MAC with station MAC\n\
                           found on interface.\n");
#endif
    printf("\
  -V, --verbose          Verbose output status.\n\
      --help     display this help and exit\n\
      --version  output version information and exit\n\
\n" );
    exit( 0 );
}

void usage( void )
{
    fprintf( stderr, "Try `%s --help' for more information.\n", program_name );
    exit( 1 );
}

void version( void )
{
    printf( "\
%s %s\n\
%s\n\
\n\
%s\n\
", INTERNAL_NAME, VER_STRING, COMPANY_NAME, LEGAL_COPYRIGHT );
    exit( 0 );
}

void printDevs( void )
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf( stderr, "Error in pcap_findalldevs: %s\n", errbuf );
        exit(1);
    }

    /* Scan the list printing every entry */
    int i = 1;
    for(d=alldevs;d;d=d->next)
    {
        printf("%i.%s ",i++, d->name);
        if (d->description)
            printf("(%s)",d->description);
        printf("\n");
    }
    pcap_freealldevs(alldevs);

    exit(0);
}

#ifdef ADDRS
int pcaps( FILE *fd, PGETADDRS addrs, char *dev, char *pUserInput )
#else
int pcaps( FILE *fd, char *dev, char *pUserInput )
#endif
{
    char bDone = 1;
    int len = 0;
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
        fprintf( stderr,
                 "Unable to open adapter - `%s'\n", dev );
        exit(1);
    }

    while (1) {    
        if ( fd == stdin )
        {
            bDone = 0;
            if ( ( ( pUserInput = dgets( fd, 512, '\n' ) ) ) == NULL )
            {
                fprintf(stderr, "%s: dgets() error\n", program_name);
                return 1;
            }
            len = strlen(pUserInput) - 1;
            if (pUserInput[len] == EOF)
            {
                /* Done */
                bDone = 1;
                pUserInput[len] = '\0'; /* Remove EOF */
            }
            if (pUserInput[len] == '\n')
                pUserInput[len] = '\0'; /* Remove \n */
        }

        // At least as long as complete Ethernet frame
        if ( checkPacketNotLen( strlen( pUserInput ), 28) )
        {
            if ( bDone )
                break;
            else
                continue;
        }

        len = strlen( pUserInput ) / 2;
        pUserInput = ( char * )hexStringToBytes( pUserInput );

#ifdef ADDRS
        if ( cMac )
            rewriteMac( pUserInput, len, addrs->mac );
        if ( cGw )
            rewriteMacGw( pUserInput, len, addrs->mac_gw );
        if ( cIpv4 )
            rewriteIpv4( pUserInput, len, addrs->ipv4 );
        if ( cIpv6 )
            rewriteIpv6( pUserInput, len, addrs->ipv6 );
#endif

        if ( cVerbose )
            printf("Packet       = %s\n", bytesToHexString( (uint8_t *)pUserInput, len*2 ));

            /* Send the packet */
        if ( pcap_sendpacket( fp, ( u_char *)pUserInput,
                              len /* size */ ) != 0 )
        {
            fprintf( stderr, "Error sending packet: %s\n", pcap_geterr( fp ) );
/*
            if ( !cCont )
                exit(1);
*/
        }

        if ( bDone )
            break;
    }

    if ( fd == stdin )
        free(pUserInput);

    return 0;
}

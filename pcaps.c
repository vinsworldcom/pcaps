#define HAVE_REMOTE

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <pcap.h>

#include "pcaps_private.h"

#include "dgets.h"
#include "getaddrs.h"
#include "hexString.h"
#include "pcaps.h"
#include "pcapsend.h"
#include "rewrite.h"

const char *program_name;

uint8_t flags = 0;

/* Prototypes */
void usage( void );
void help( void );
void version( void );
void printDevs( void );
int getdata( FILE *, PGETADDRS, uint8_t, char *, char * );

int main( int argc, char *argv[] )
{
    /* variables */
    program_name = argv[0];
    FILE *fd;
    GETADDRS addrs;

    /* START: command line options variables */
    char arglist[10] = "DViIgm";
    static int show_help    = 0;
    static int show_version = 0;
    int ret, opt_index;
    struct option cloptions[] =
    {
        {"devices"    , no_argument       , NULL,         'D'},
        {"verbose"    , no_argument       , NULL,         'V'},
        {"ipv4"       , no_argument       , NULL,         'i'},
        {"ipv6"       , no_argument       , NULL,         'I'},
        {"gatewaymac" , no_argument       , NULL,         'g'},
        {"mac"        , no_argument       , NULL,         'm'},
        {"help"     , no_argument       , &show_help,    1 },
        {"version"  , no_argument       , &show_version, 1 },
        {0, 0, 0, 0}
    };
    /* END: command line options variables */

    //strcat (arglist, "");

    /* parse command line options */
    while ( ( ret = getopt_long( argc, argv, arglist, cloptions, &opt_index ) ) != -1 )
    {
        switch ( ret )
        {
            case 'D':
                printDevs();

                case 'V':
                flags = flags|VERBOSE;
                break;

                case 'i':
                flags = flags|RW_IP4;
                break;

                case 'I':
                flags = flags|RW_IP6;
                break;

                case 'g':
                flags = flags|RW_MGW;
                break;

                case 'm':
                flags = flags|RW_MAC;
                break;

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

    if ( ( argc >= 1 ) && ( flags&RW_ALL ) )
    {
        addrs = getaddrs( argv[0] );
        if ( addrs.error )
            return 1;
        if ( flags&VERBOSE )
        {
            printf("MAC Address  = %s\n", addrs.mac);
            printf("MAC Gateway  = %s\n", addrs.mac_gw);
            printf("IPv4 Address = %s\n", addrs.ipv4);
            printf("IPv4 Gateway = %s\n", addrs.ipv4_gw);
            printf("IPv6 Address = %s\n", addrs.ipv6);
            printf("IPv6 Gateway = %s\n", addrs.ipv6_gw);
        }
    }

    /* no input - get from STDIN */
    if (argc == 1)
    {
        fd = stdin;
        getdata(fd, &addrs, flags, argv[0], 0);
    }
    else if (argc > 1)
    {
        /* loop on remaining argv */
        fd = 0;
        int i;
        for (i = 1; i < argc; i++)
            getdata(fd, &addrs, flags, argv[0], argv[i]);
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

    printf("\
  -i, --ipv4             Overwrite source IPv4 with station IPv4\n\
                           found on interface.\n\
  -I, --ipv6             Overwrite source IPv6 with station IPv6\n\
                           found on interface.\n\
                         NOTE: rewriting IPv4/v6 addresses will\n\
                           attempt to recalculate checksums in IPv4\n\
                           and upper layers.\n");
/*
    printf("\
  -c, --continue         Try to continue on some errors instead\n\
                           of exit.\n");
*/
    printf("\
  -g, --gatewaymac       Overwrite destination MAC with gateway MAC\n\
                           found from ARP on interface.\n\
  -m, --mac              Overwrite source MAC with station MAC\n\
                           found on interface.\n");
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
    for( d = alldevs; d; d = d->next )
    {
        printf( "%i.%s ",i++, d->name );
        if ( d->description )
            printf( "(%s)",d->description );
        printf( "\n" );
    }
    pcap_freealldevs( alldevs );

    exit(0);
}

int getdata( FILE *fd, PGETADDRS addrs, uint8_t flags, char *dev, char *pUserInput )
{
    char bDone = 1;
    int len = 0;

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

        len = strlen( pUserInput ) / 2;
        pUserInput = ( char * )hexStringToBytes( pUserInput );

        if ( pcapsend( addrs, flags, dev, pUserInput, len ) == 0 )
        {
            // do nothing
        }

        if ( bDone )
            break;
    }

    if ( fd == stdin )
        free(pUserInput);

    return 0;
}

#define _WIN32_WINNT 0x0601 // FirstGatewayAddress as member of PIP_ADAPTER_ADDRESSES

#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#include "getaddrs.h"

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

/* Note: could also use malloc() and free() */
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

GETADDRS getaddrs( char *adapter )
{
    // addrs structure and initialize
    GETADDRS addrs;
    strcpy(addrs.mac, "");
    strcpy(addrs.mac_gw, "");
    strcpy(addrs.ipv4, "");
    strcpy(addrs.ipv4_gw, "");
    strcpy(addrs.ipv6, "");
    strcpy(addrs.ipv6_gw, "");
    addrs.error = 1;

    char ADDR_PART[2];
    DWORD dwRetVal = 0;
    unsigned int i = 0;

    // Set the flags to pass to GetAdaptersAddresses
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_FRIENDLY_NAME
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_ANYCAST;

    // default to unspecified address family (both)
    ULONG family = AF_UNSPEC;

    LPVOID lpMsgBuf = NULL;

    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    ULONG Iterations = 0;

    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    PIP_ADAPTER_GATEWAY_ADDRESS pGateway = NULL;

    // Allocate a 15 KB buffer to start with.
    outBufLen = WORKING_BUFFER_SIZE;

    do {
        pAddresses = (IP_ADAPTER_ADDRESSES *) MALLOC(outBufLen);
        if (pAddresses == NULL) {
            fprintf( stderr, 
                     "malloc failed for IP_ADAPTER_ADDRESSES struct\n" );
            return addrs;
        }

        dwRetVal =
            GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            FREE(pAddresses);
            pAddresses = NULL;
        } else {
            break;
        }
        Iterations++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

    if (dwRetVal == NO_ERROR) {
        // If successful, output some information from the data we received
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            if ( strstr( adapter, pCurrAddresses->AdapterName ) != NULL )
            {
                void * addr;
                char ipstr[INET6_ADDRSTRLEN]; /* Provide big enough buffer, ipv6 should be the biggest */

                // Mac
                if (pCurrAddresses->PhysicalAddressLength != 0)
                {
                    for (i = 0; i < (int) pCurrAddresses->PhysicalAddressLength;
                         i++) 
                    {
                        sprintf( ADDR_PART, "%.2X", 
                                (int) pCurrAddresses->PhysicalAddress[i] );
                        strcat( addrs.mac, ADDR_PART );
                        addrs.error = 0;
                    }
#ifdef DEBUG
                    printf("getaddrs.c - MAC Address  = %s\n", addrs.mac);
#endif
                }
                // gateway
                if ( ( pGateway = pCurrAddresses->FirstGatewayAddress ) != NULL ) {
                    for (i = 0; pGateway != NULL; i++)
                    {
                        // IPv4
                        if ( (((struct sockaddr *)pGateway->Address.lpSockaddr)->sa_family == AF_INET)
                            && ( strlen( addrs.ipv4_gw ) == 0 ) )
                        {
                            addr = &((struct sockaddr_in *)pGateway->Address.lpSockaddr)->sin_addr;
                            inet_ntop(AF_INET, addr, (PSTR)ipstr, sizeof(ipstr));
                            strcpy( addrs.ipv4_gw, ipstr);
//                            sprintf( addrs.ipv4_gw, "%s", bytesToHexString( addr, 8 ) );
                            addrs.error = 0;
#ifdef DEBUG
                            printf("getaddrs.c - IPv4 Gateway = %s\n", addrs.ipv4_gw);
#endif
                            if ( strlen( addrs.ipv4_gw ) != 0 )
                            {
                                DWORD dwRetValmac;
                                IPAddr DestIp = 0;
                                ULONG MacAddr[2];       /* for 6-byte hardware addresses */
                                ULONG PhysAddrLen = 6;  /* default to length of six bytes */
                                BYTE *bPhysAddr;
                                unsigned int i;

                                DestIp = inet_addr( ipstr );
                                memset(&MacAddr, 0xff, sizeof (MacAddr));
                                dwRetValmac = SendARP(DestIp, 0, (PULONG)&MacAddr, &PhysAddrLen);

                                if (dwRetValmac == NO_ERROR)
                                {
                                    bPhysAddr = (BYTE *) & MacAddr;
                                    if (PhysAddrLen)
                                    {
                                        for (i = 0; i < (int) PhysAddrLen; i++)
                                        {
                                            sprintf( ADDR_PART, "%.2X", 
                                                (int) bPhysAddr[i] );
                                            strcat( addrs.mac_gw, ADDR_PART );
                                            addrs.error = 0;
                                        }
#ifdef DEBUG
                                        printf("getaddrs.c - MAC Gateway  = %s\n", addrs.mac_gw);
#endif
                                    }
                                    else
                                        fprintf( stderr,
                                            "Warning: SendArp completed successfully, but returned length=0\n" );
                                }
                                else
                                {
                                    fprintf( stderr, "SendARP() error: %d - ", (int)dwRetValmac);
                                    switch (dwRetValmac)
                                    {
                                        case ERROR_GEN_FAILURE:
                                            fprintf( stderr, "(ERROR_GEN_FAILURE)\n");
                                            break;
                                        case ERROR_INVALID_PARAMETER:
                                            fprintf( stderr, "(ERROR_INVALID_PARAMETER)\n");
                                            break;
                                        case ERROR_INVALID_USER_BUFFER:
                                            fprintf( stderr, "(ERROR_INVALID_USER_BUFFER)\n");
                                            break;
                                        case ERROR_BAD_NET_NAME:
                                            fprintf( stderr, "(ERROR_GEN_FAILURE)\n");
                                            break;
                                        case ERROR_BUFFER_OVERFLOW:
                                            fprintf( stderr, "(ERROR_BUFFER_OVERFLOW)\n");
                                            break;
                                        case ERROR_NOT_FOUND:
                                            fprintf( stderr, "(ERROR_NOT_FOUND)\n");
                                            break;
                                        default:
                                            fprintf( stderr, "\n");
                                            break;
                                    }
                                }
                            }
                        }
                        // IPv6
                        else if ( (((struct sockaddr *)pGateway->Address.lpSockaddr)->sa_family == AF_INET6)
                            && ( strlen( addrs.ipv6_gw ) == 0 ) )
                        {
                            addr = &((struct sockaddr_in6 *)pGateway->Address.lpSockaddr)->sin6_addr;
                            inet_ntop(AF_INET6, addr, (PSTR)ipstr, sizeof(ipstr));
                            strcpy( addrs.ipv6_gw, ipstr);
//                            sprintf( addrs.ipv6_gw, "%s", bytesToHexString( addr, 32 ) );
                            addrs.error = 0;
#ifdef DEBUG
                            printf("getaddrs.c - IPv6 Gateway = %s\n", addrs.ipv6_gw);
#endif
                        }
                        pGateway = pGateway->Next;
                    }
                }

                // IP
                if ( ( pUnicast = pCurrAddresses->FirstUnicastAddress ) != NULL ) {
                    for (i = 0; pUnicast != NULL; i++)
                    {
                        // IPv4
                        if ( (((struct sockaddr *)pUnicast->Address.lpSockaddr)->sa_family == AF_INET)
                            && ( strlen( addrs.ipv4 ) == 0 ) )
                        {
                            addr = &((struct sockaddr_in *)pUnicast->Address.lpSockaddr)->sin_addr;
                            inet_ntop(AF_INET, addr, (PSTR)ipstr, sizeof(ipstr));
                            strcpy( addrs.ipv4, ipstr);
//                            sprintf( addrs.ipv4, "%s", bytesToHexString( addr, 8 ) );
                            addrs.error = 0;
#ifdef DEBUG
                            printf("getaddrs.c - IPv4 Address = %s\n", addrs.ipv4);
#endif
                        }
                        // IPv6
                        else if ( (((struct sockaddr *)pUnicast->Address.lpSockaddr)->sa_family == AF_INET6)
                            && ( strlen( addrs.ipv6 ) == 0 ) )
                        {
                            addr = &((struct sockaddr_in6 *)pUnicast->Address.lpSockaddr)->sin6_addr;
                            inet_ntop(AF_INET6, addr, (PSTR)ipstr, sizeof(ipstr));
                            strcpy( addrs.ipv6, ipstr);
//                            sprintf( addrs.ipv6, "%s", bytesToHexString( addr, 32 ) );
                            addrs.error = 0;
#ifdef DEBUG
                            printf("getaddrs.c - IPv6 Address = %s\n", addrs.ipv6);
#endif
                        }
                        pUnicast = pUnicast->Next;
                    }
                }
                break;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    } else {
        printf("GetAdaptersAddresses() error: %d - ", (int)dwRetVal);
        if (dwRetVal == ERROR_NO_DATA)
            fprintf( stderr, "No addresses were found for the requested parameters\n" );
        else {
            if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
                NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
                // Default language
                (LPTSTR) & lpMsgBuf, 0, NULL))
            {
                fprintf( stderr, "%s\n", (char *)lpMsgBuf);
                LocalFree(lpMsgBuf);
                if (pAddresses)
                    FREE(pAddresses);
                return addrs;
            }
        }
    }

    if (pAddresses) {
        FREE(pAddresses);
    }
    return addrs;
}

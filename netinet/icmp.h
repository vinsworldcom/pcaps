#ifndef NETINET_ICMP_H
#define NETINET_ICMP_H

#include <ws2tcpip.h>
#include <stdint.h>

#define ICMP_TYPE_ECHO_REPLY                         0
#define ICMP_TYPE_DESTINATION_UNREACHABLE            3
  #define ICMP_CODE_NETWORK_UNREACHABLE                  0
  #define ICMP_CODE_HOST_UNREACHABLE                     1
  #define ICMP_CODE_PROTOCOL_UNREACHABLE                 2
  #define ICMP_CODE_PORT_UNREACHABLE                     3
  #define ICMP_CODE_DATAGRAM_TOO_BIG                     4
  #define ICMP_CODE_SOURCE_ROUTE_FAILED                  5
  #define ICMP_CODE_DESTINATION_NETWORK_UNKNOWN          6
  #define ICMP_CODE_DESTINATION_HOST_UNKNOWN             7
  #define ICMP_CODE_SOURCE_HOST_ISOLATED                 8
  #define ICMP_CODE_DESTINATION_NETWORK_ADMIN_PROHIBITED 9
  #define ICMP_CODE_DESTINATION_HOST_ADMIN_PROHIBITED   10
  #define ICMP_CODE_NETWORK_UNREACHABLE_TOS             11
  #define ICMP_CODE_HOST_UNREACHABLE_TOS                12
  #define ICMP_CODE_COMMUNICATION_ADMIN_PROHIBITED      13
  #define ICMP_CODE_HOST_PRECEDENCE_VIOLATION           14
  #define ICMP_CODE_PRECEDENCE_CUTOFF_IN_EFFECT         15
#define ICMP_TYPE_SOURCE_QUENCH                      4
#define ICMP_TYPE_REDIRECT                           5
  #define ICMP_CODE_NETWORK_ERROR                        0
  #define ICMP_CODE_HOST_ERROR                           1
  #define ICMP_CODE_TOS_NETWORK_ERROR                    2
  #define ICMP_CODE_TOS_HOST_ERROR                       3
#define ICMP_TYPE_ALTERNATE_HOST_ADDRESS             6
#define ICMP_TYPE_ECHO_REQUEST                       8
#define ICMP_TYPE_ROUTER_ADVERTISEMENT               9
  #define ICMP_CODE_NORMAL                               0
  #define ICMP_CODE_NOT_COMMON_TRAFFIC                  16
#define ICMP_TYPE_ROUTER_SOLICITATION               10
#define ICMP_TYPE_TIME_EXCEEDED                     11
  #define ICMP_CODE_TIME_EXCEEDED_TTL                    0
  #define ICMP_CODE_TIME_EXCEEDED_FRAG_TIMEOUT           1
#define ICMP_TYPE_PARAMETER_PROBLEM                 12
  #define ICMP_CODE_IP_HEADER_INVALID                    0
  #define ICMP_CODE_REQUIRED_OPTION_MISSING              1
#define ICMP_TYPE_TIMESTAMP_REQUEST                 13
#define ICMP_TYPE_TIMESTAMP_REPLY                   14
#define ICMP_TYPE_INFORMATION_REQUEST               15
#define ICMP_TYPE_INFORMATION_REPLY                 16
#define ICMP_TYPE_ADDRESS_MASK_REQUEST              17
#define ICMP_TYPE_ADDRESS_MASK_REPLY                18
#define ICMP_TYPE_TRACEROUTE                        30
  #define ICMP_CODE_OUTBOUND_PACKET_FORWARDED            0
  #define ICMP_CODE_OUTBOUND_PACKET_DISCARDED_NO_ROUTE   1
#define ICMP_TYPE_CONVERSION_ERROR                  31
#define ICMP_TYPE_MOBILE_HOST_REDIRECT              32
#define ICMP_TYPE_IPV6_WHERE_ARE_YOU                33
#define ICMP_TYPE_IPV6_I_AM_HERE                    34
#define ICMP_TYPE_MOBILE_REGISTRATION_REQUEST       35
#define ICMP_TYPE_MOBILE_REGISTRATION_REPLY         36
#define ICMP_TYPE_DOMAIN_NAME_REQUEST               37
#define ICMP_TYPE_DOMAIN_NAME_REPLY                 38
#define ICMP_TYPE_SKIP_ALGORITHM_DISCOVERY_PROTOCOL 39
#define ICMP_TYPE_PHOTURIS                          40

// ICMP Header Structure
typedef struct icmp_hdr
{
   uint8_t  icmp_type;
   uint8_t  icmp_code;
   uint16_t icmp_checksum;
} ICMP_HDR, *PICMP_HDR;

#define ICMP_HDRLEN sizeof( ICMP_HDR )

#endif
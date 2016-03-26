#ifndef REWRITE_H
#define REWRITE_H

int checkPacketNotLen( int, int );

void rewriteMac( char *, int, char * );
void rewriteMacGw( char *, int, char * );
void rewriteIpv4( char *, int, char * );
void rewriteIpv6( char *, int, char * );

#endif

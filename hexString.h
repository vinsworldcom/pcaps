#ifndef HEXSTRING_H
#define HEXSTRING_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint8_t *hexStringToBytes(char *);
char *bytesToHexString( uint8_t *, size_t );

#endif

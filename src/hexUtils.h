#ifndef H_FIO_APP_HEX_UTILS
#define H_FIO_APP_HEX_UTILS

#include "common.h"

size_t decode_hex(const char* inStr, uint8_t* outBuffer, size_t outMaxSize);
size_t encode_hex(const uint8_t* bytes, size_t bytesLength, char* outString, size_t outMaxSize);

#ifdef DEVEL
void run_hex_test();
#endif // DEVEL

#endif // H_CARDANO_APP_HEX_UTILS

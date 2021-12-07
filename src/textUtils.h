#ifndef H_FIO_APP_TEXT_UTILS
#define H_FIO_APP_TEXT_UTILS

#include "common.h"

size_t str_formatFIOAmount(uint64_t amount, char* out, size_t outSize);

size_t str_formatUint64(uint64_t number, char* out, size_t outSize);

void str_validateTextBuffer(const uint8_t* text, size_t textSize);
void str_validateNullTerminatedTextBuffer(const uint8_t* text, size_t textSize);

#ifdef DEVEL
void run_textUtils_test();
#endif // DEVEL

#endif // H_CARDANO_FIO_TEXT_UTILS

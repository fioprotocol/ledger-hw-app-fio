#ifndef H_FIO_APP_BIP44
#define H_FIO_APP_BIP44

#include "common.h"

#define BIP44_MAX_PATH_ELEMENTS 10u
// each element in path is uint32, so at most 10 decimal digits
// plus ' for hardened plus / as a separator, plus the initial m
#define BIP44_MAX_PATH_STRING_LENGTH (1 + 12 * BIP44_MAX_PATH_ELEMENTS)

typedef struct {
	uint32_t path[BIP44_MAX_PATH_ELEMENTS];
	uint32_t length;
} bip44_path_t;


static const uint32_t PURPOSE_FIO = 44;
static const uint32_t COIN_TYPE_FIO = 235;

static const uint32_t HARDENED_BIP32 = ((uint32_t) 1 << 31);

size_t bip44_parseFromWire(
        bip44_path_t* pathSpec,
        const uint8_t* dataBuffer, size_t dataSize
);

// Indexes into pathSpec
enum {
	BIP44_I_PURPOSE = 0,
	BIP44_I_COIN_TYPE = 1,
	BIP44_I_ACCOUNT = 2,
	BIP44_I_CHAIN = 3,
	BIP44_I_ADDRESS = 4,
	BIP44_I_REST = 5,
};


bool bip44_hasValidFIOPrefix(const bip44_path_t* pathSpec);

bool bip44_containsAddress(const bip44_path_t* pathSpec);
bool bip44_hasReasonableAddress(const bip44_path_t* pathSpec);

bool bip44_containsMoreThanAddress(const bip44_path_t* pathSpec);

bool isHardened(uint32_t value);
uint32_t unharden(uint32_t value);

size_t bip44_printToStr(const bip44_path_t*, char* out, size_t outSize);


#ifdef DEVEL
void run_bip44_test();
void bip44_PRINTF(const bip44_path_t* pathSpec);
#define BIP44_PRINTF(PATH) bip44_PRINTF(PATH)
#else
#define BIP44_PRINTF(PATH)
#endif // DEVEL

#endif // H_FIO_APP_BIP44

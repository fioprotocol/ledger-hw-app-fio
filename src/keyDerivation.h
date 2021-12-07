#ifndef H_FIO_APP_KEY_DERIVATION
#define H_FIO_APP_KEY_DERIVATION

#include "common.h"
#include "handlers.h"
#include "bip44.h"


#define PUBLIC_KEY_SIZE      (32)
#define CHAIN_CODE_SIZE      (32)

typedef cx_ecfp_private_key_t private_key_t;
typedef cx_ecfp_public_key_t public_key_t;

typedef struct {
	uint8_t code[CHAIN_CODE_SIZE];
} chain_code_t;

void derivePrivateKey(
        const bip44_path_t* pathSpec,
        private_key_t* privateKey // output
);


void derivePublicKey(
        const bip44_path_t* pathSpec,
        public_key_t* out
);


#ifdef DEVEL
void run_key_derivation_test();
#endif // DEVEL

#endif // H_FIO_APP_KEY_DERIVATION

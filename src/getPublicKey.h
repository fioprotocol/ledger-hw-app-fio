#ifndef H_FIO_APP_GET_PUBLIC_KEY
#define H_FIO_APP_GET_PUBLIC_KEY

#include "common.h"
#include "handlers.h"
#include "bip44.h"
#include "keyDerivation.h"

#define MAX_PUBLIC_KEYS 1000

typedef enum {
	GET_KEY_STAGE_NONE = 0,
	GET_KEY_STAGE_INIT = 20,
} get_key_stage_t;

typedef enum {
	P1_SHOW_PUBKEY = 1,
	P1_DO_NOT_SHOW_PUBKEY = 2,
} get_key_p1_t;

typedef struct {
	get_key_stage_t stage;
	get_key_p1_t show_or_not;

	bip44_path_t pathSpec;
	public_key_t pubKey;

	uint16_t responseReadyMagic;

	int ui_step;
} ins_get_key_context_t;

handler_fn_t getPublicKey_handleAPDU;

#endif // H_FIO_APP_GET_PUBLIC_KEY

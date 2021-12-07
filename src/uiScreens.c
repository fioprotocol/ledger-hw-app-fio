#include "uiScreens.h"
#include "hexUtils.h"
#include "textUtils.h"
#include "eos_utils.h"
#include "fio.h"

__noinline_due_to_stack__
void ui_displayPathScreen(
        const char* screenHeader,
        const bip44_path_t* path,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(screenHeader) > 0);
	ASSERT(strlen(screenHeader) < BUFFER_SIZE_PARANOIA);

	char pathStr[1 + BIP44_MAX_PATH_STRING_LENGTH];
	bip44_printToStr(path, pathStr, SIZEOF(pathStr));

	ui_displayPaginatedText(
	        screenHeader,
	        pathStr,
	        callback
	);
}

__noinline_due_to_stack__
void ui_displayUint64Screen(
        const char* screenHeader,
        uint64_t value,
        ui_callback_fn_t callback
)
{
	char valueStr[30];
	str_formatUint64(value, valueStr, SIZEOF(valueStr));

	ui_displayPaginatedText(
	        screenHeader,
	        valueStr,
	        callback
	);
}

__noinline_due_to_stack__
void ui_displayFIOAmountScreen(
        const char* screenHeader,
        uint64_t amount,
        ui_callback_fn_t callback
)
{
	char buf[35]; //20 digits 1x '.', 4x '.', ' FIO', terminating 0 + reserve
	str_formatFIOAmount(amount, buf, SIZEOF(buf));
	ui_displayPaginatedText(screenHeader, buf, callback);

}


__noinline_due_to_stack__
void ui_displayHexBufferScreen(
        const char* screenHeader,
        const uint8_t* buffer, size_t bufferSize,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(screenHeader) > 0);
	ASSERT(strlen(screenHeader) < BUFFER_SIZE_PARANOIA);
	ASSERT(bufferSize > 0);
	ASSERT(bufferSize <= 65); // this is used for hashes, and pubkeys, they are all smaller

	char bufferHex[2 * 65 + 1];
	explicit_bzero(bufferHex, SIZEOF(bufferHex));

	size_t length = encode_hex(
	                        buffer, bufferSize,
	                        bufferHex, SIZEOF(bufferHex)
	                );
	ASSERT(length == strlen(bufferHex));
	ASSERT(length == 2 * bufferSize);

	ui_displayPaginatedText(
	        screenHeader,
	        bufferHex,
	        callback
	);
}

__noinline_due_to_stack__
void ui_displayPubkeyScreen(
        const char* screenHeader,
        const public_key_t* pubkey,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(screenHeader) > 0);
	ASSERT(strlen(screenHeader) < BUFFER_SIZE_PARANOIA);
    
	char buffer[MAX_WIF_PUBKEY_LENGTH + 1];
	uint32_t outlen = public_key_to_wif(pubkey->W, SIZEOF(pubkey->W), buffer, SIZEOF(buffer));
	ASSERT(outlen < MAX_WIF_PUBKEY_LENGTH + 1);
	buffer[outlen] = 0;

	ui_displayPaginatedText(
	        screenHeader,
	        buffer,
	        callback
	);
}



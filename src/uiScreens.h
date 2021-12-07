#ifndef H_FIO_APP_UI_SCREENS
#define H_FIO_APP_UI_SCREENS

#include "uiHelpers.h"
#include "keyDerivation.h"
#include "bip44.h"

__noinline_due_to_stack__
void ui_displayPathScreen(
        const char* screenHeader,
        const bip44_path_t* path,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayFIOAmountScreen(
        const char* screenHeader,
        uint64_t amount,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayUint64Screen(
        const char* screenHeader,
        uint64_t value,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayHexBufferScreen(
        const char* screenHeader,
        const uint8_t* buffer, size_t bufferSize,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayPubkeyScreen(
        const char* screenHeader,
        const public_key_t* pubkey,
        ui_callback_fn_t callback
);

#ifdef DEVEL
void run_uiScreens_test();
#endif // DEVEL

#endif // H_FIO_APP_UI_SCREENS

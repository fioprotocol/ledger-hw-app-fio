#ifdef DEVEL

#include "runTests.h"
#include "testUtils.h"
#include "hexUtils.h"
#include "hash.h"
#include "bip44.h"
#include "endian.h"
#include "keyDerivation.h"
#include "textUtils.h"
#include "uiHelpers.h"
#include "uiScreens.h"


void handleRunTests(
        uint8_t p1 MARK_UNUSED,
        uint8_t p2 MARK_UNUSED,
        uint8_t *wireBuffer MARK_UNUSED,
        size_t wireSize MARK_UNUSED,
        bool isNewCall MARK_UNUSED
)
{
	// Note: Make sure to have RESET_ON_CRASH flag disabled
	// as it interferes with tests verifying assertions
	BEGIN_ASSERT_NOEXCEPT {
		PRINTF("Running tests\n");
		run_hex_test();
		run_endian_test();
		run_textUtils_test();
		run_bip44_test();
		run_key_derivation_test();
		PRINTF("All tests done\n");
	} END_ASSERT_NOEXCEPT;

	io_send_buf(SUCCESS, NULL, 0);
	ui_idle();
}

#endif // DEVEL

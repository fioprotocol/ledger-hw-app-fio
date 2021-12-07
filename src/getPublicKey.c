#include "state.h"
#include "securityPolicy.h"
#include "uiHelpers.h"
#include "uiScreens.h"
#include "getPublicKey.h"
#include "utils.h"
#include "eos_utils.h"

static int16_t RESPONSE_READY_MAGIC = 23456;

static ins_get_key_context_t* ctx = &(instructionState.getKeyContext);

// ctx->ui_state is shared between the intertwined UI state machines below
// it should be set to this value at the beginning and after a UI state machine is finished
static int UI_STEP_NONE = 0;

static inline void CHECK_STAGE(get_key_stage_t expected)
{
	VALIDATE(ctx->stage == expected, ERR_INVALID_STATE);
}

static void advanceStage()
{
	TRACE("Advancing from stage: %d", ctx->stage);

	switch (ctx->stage) {

	case GET_KEY_STAGE_INIT:
		ctx->stage = GET_KEY_STAGE_NONE;
		ui_idle(); // we are done with this key export
		break;

	default:
		ASSERT(false);
	}
}

// ============================== Derivation and UI state machine ==============================

enum {
	GET_KEY_UI_STEP_WARNING = 200,
	GET_KEY_UI_STEP_DISPLAY_PATH,
	GET_KEY_UI_STEP_DISPLAY_PUBKEY,
	GET_KEY_UI_STEP_CONFIRM,
	GET_KEY_UI_STEP_RESPOND,
	GET_KEY_UI_STEP_INVALID,
} ;

static void getPublicKey_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = getPublicKey_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(GET_KEY_UI_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
	}
	UI_STEP(GET_KEY_UI_STEP_DISPLAY_PATH) {
		ui_displayPathScreen("Export public key", &ctx->pathSpec, this_fn);
	}
	UI_STEP(GET_KEY_UI_STEP_DISPLAY_PUBKEY) {
		ui_displayPubkeyScreen("Public key", &ctx->pubKey, this_fn);
	}
	UI_STEP(GET_KEY_UI_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Confirm export",
		        "public key?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(GET_KEY_UI_STEP_RESPOND) {
		ASSERT(ctx->responseReadyMagic == RESPONSE_READY_MAGIC);

		memmove(G_io_apdu_buffer, ctx->pubKey.W, SIZEOF(ctx->pubKey.W));
		uint32_t wifkeylen = public_key_to_wif(ctx->pubKey.W, SIZEOF(ctx->pubKey.W), 
				(char *)G_io_apdu_buffer + SIZEOF(ctx->pubKey.W), MAX_WIF_PUBKEY_LENGTH);
		//we do not copy trailing 0
		io_send_buf(SUCCESS, G_io_apdu_buffer, SIZEOF(ctx->pubKey.W) + wifkeylen - 1);

		ctx->responseReadyMagic = 0; // just for safety
		ui_displayBusy(); // needs to happen after I/O

		TRACE("Export done.");

		advanceStage();
	}
	UI_STEP_END(GET_KEY_UI_STEP_INVALID);
}

// derive the key described by ctx->pathSpec and run the ui state machine accordingly
static void runGetPublicKeyUIFlow()
{
	ASSERT(ctx->ui_step == UI_STEP_NONE); // make sure no ui state machine is running

	ctx->responseReadyMagic = 0;

	// Check security policy
	security_policy_t policy = policyForGetPublicKey(&ctx->pathSpec, ctx->show_or_not);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// Calculation
		derivePublicKey(
		        & ctx->pathSpec,
		        & ctx->pubKey
		);
		ctx->responseReadyMagic = RESPONSE_READY_MAGIC;
	}

	switch (policy) {
#	define  CASE(policy, step) case policy: {ctx->ui_step = step; break;}
		CASE(POLICY_PROMPT_WARN_UNUSUAL,    GET_KEY_UI_STEP_WARNING);
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, GET_KEY_UI_STEP_DISPLAY_PUBKEY);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT,   GET_KEY_UI_STEP_RESPOND);
#	undef   CASE
	default:
		ASSERT(false);
	}

	getPublicKey_ui_runStep();
}

// ============================== MAIN HANDLER ==============================

void getPublicKey_handleAPDU(
        uint8_t p1,
        uint8_t p2,
        uint8_t* wireDataBuffer,
        size_t wireDataSize,
        bool isNewCall
)
{
	VALIDATE(isNewCall, ERR_INVALID_STATE);
	VALIDATE(p1 == P1_SHOW_PUBKEY || p1 == P1_DO_NOT_SHOW_PUBKEY, ERR_INVALID_REQUEST_PARAMETERS);
	VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);

	explicit_bzero(ctx, SIZEOF(*ctx));
	ctx->stage = GET_KEY_STAGE_INIT;
	ctx->ui_step = UI_STEP_NONE;

	CHECK_STAGE(GET_KEY_STAGE_INIT);
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

	{
		ctx->show_or_not = p1;

		// parse
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		size_t parsedSize = bip44_parseFromWire(&ctx->pathSpec, wireDataBuffer, wireDataSize);
		VALIDATE(parsedSize == wireDataSize, ERR_INVALID_DATA);
	}

	runGetPublicKeyUIFlow();
}

#include "common.h"
#include "handlers.h"

#include "getSerial.h"
#include "state.h"
#include "hash.h"
#include "endian.h"
#include "eos_utils.h"
#include "securityPolicy.h"
#include "uiHelpers.h"
#include "uiScreens.h"
#include "textUtils.h"

static ins_sign_transaction_context_t* ctx = &(instructionState.signTransactionContext);

typedef enum {
	SIGN_STAGE_NONE = 0,
	SIGN_STAGE_INIT = 23,
	SIGN_STAGE_HEADER = 24,
	SIGN_STAGE_ACTION_HEADER = 25,
	SIGN_STAGE_ACTION_AUTHORIZATION = 26,
	SIGN_STAGE_ACTION_DATA = 27,
	SIGN_STAGE_WITNESS = 28,
} sign_tx_stage_t;

// this is supposed to be called at the beginning of each APDU handler
static inline void CHECK_STAGE(sign_tx_stage_t expected)
{
	VALIDATE(ctx->stage == expected, ERR_INVALID_STATE);
}

// advances the stage of the main state machine
static inline void advanceStage()
{
	TRACE("Advancing sign tx stage from: %d", ctx->stage);

	switch (ctx->stage) {

	case SIGN_STAGE_INIT:
		ctx->stage = SIGN_STAGE_HEADER;
		break;

	case SIGN_STAGE_HEADER:
		ctx->stage = SIGN_STAGE_ACTION_HEADER;
		break;

	case SIGN_STAGE_ACTION_HEADER:
		ctx->stage = SIGN_STAGE_ACTION_AUTHORIZATION;
		break;

	case SIGN_STAGE_ACTION_AUTHORIZATION:
		ctx->stage = SIGN_STAGE_ACTION_DATA;
		break;

	case SIGN_STAGE_ACTION_DATA:
		ctx->stage = SIGN_STAGE_WITNESS;
		break;

	case SIGN_STAGE_WITNESS:
		ctx->stage = SIGN_STAGE_NONE;
		ui_idle(); // we are done with this tx
		break;

	case SIGN_STAGE_NONE:
		// advanceStage() not supposed to be called after tx processing is finished
		ASSERT(false);
	default:
		ASSERT(false);
	}

	TRACE("Advancing sign tx stage to: %d", ctx->stage);
}

void respondSuccessEmptyMsg()
{
	TRACE();
	io_send_buf(SUCCESS, NULL, 0);
	ui_displayBusy(); // needs to happen after I/O
}

//Taken from EOS app. Needed to produce signatures.
uint8_t const SECP256K1_N[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                               0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                               0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
                              };

// ============================== INIT ==============================
enum {
	HANDLE_INIT_STEP_DISPLAY_DETAILS = 100,
	HANDLE_INIT_STEP_RESPOND,
	HANDLE_INIT_STEP_INVALID,
} ;

static void signTx_handleInit_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleInit_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_INIT_STEP_DISPLAY_DETAILS) {
		switch(ctx->network) {
#	define  CASE(NETWORK, CHAIN_STRING) case NETWORK: {ui_displayPaginatedText("Chain", CHAIN_STRING, this_fn); break;}
			CASE(NETWORK_MAINNET, "Mainnet");
			CASE(NETWORK_TESTNET, "Testnet");
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	UI_STEP(HANDLE_INIT_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}

	UI_STEP_END(HANDLE_INIT_STEP_INVALID);
}

__noinline_due_to_stack__
void signTx_handleInitAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_INIT);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t chainId[32];
		}* wireData = (void*) wireDataBuffer;

		VALIDATE(SIZEOF(*wireData) == wireDataSize, ERR_INVALID_DATA);

		TRACE("SHA_256_init");
		sha_256_init(&ctx->hashContext);
		sha_256_append(&ctx->hashContext, wireData->chainId, SIZEOF(wireData->chainId));

		ctx->network = getNetworkByChainId(wireData->chainId, SIZEOF(wireData->chainId));
		TRACE("Network %d:", ctx->network);
	}

	security_policy_t policy = policyForSignTxInit(ctx->network);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_INIT_STEP_DISPLAY_DETAILS);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleInit_ui_runStep();
}

// ============================== HEADER ==============================
enum {
	HANDLE_HEADER_STEP_EXPIRATION = 200,
	HANDLE_HEADER_STEP_REF_BLOCK_NUM,
	HANDLE_HEADER_STEP_REF_BLOCK_PREFIX,
	HANDLE_HEADER_STEP_RESPOND,
	HANDLE_HEADER_STEP_INVALID,
} ;

static void signTx_handleHeader_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleHeader_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	/*	UI_STEP(HANDLE_HEADER_STEP_EXPIRATION) {
			ui_displayTimeScreen(
					"Expiration",
					ctx->expiration,
					this_fn
			);
		}

		UI_STEP(HANDLE_HEADER_STEP_REF_BLOCK_NUM) {
			ui_displayUint64Screen(
					"Ref Block Num",
					ctx->refBlockNum,
					this_fn
			);
		}

		UI_STEP(HANDLE_HEADER_STEP_REF_BLOCK_PREFIX) {
			ui_displayUint64Screen(
					"Ref Block Prefix",
					ctx->refBlockPrefix,
					this_fn
			);
		}*/

	UI_STEP(HANDLE_HEADER_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}

	UI_STEP_END(HANDLE_HEADER_STEP_INVALID);
}

__noinline_due_to_stack__
void signTx_handleHeaderAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_HEADER);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t expiration[4];
			uint8_t refBlockNum[2];
			uint8_t refBlockPrefix[4];
		}* wireData = (void*) wireDataBuffer;

		VALIDATE(SIZEOF(*wireData) == wireDataSize, ERR_INVALID_DATA);

		ctx->expiration = u4be_read(wireData->expiration);
		sha_256_append(&ctx->hashContext, (uint8_t *)&ctx->expiration, sizeof(ctx->expiration));

		ctx->refBlockNum = u2be_read(wireData->refBlockNum);
		sha_256_append(&ctx->hashContext, (uint8_t *)&ctx->refBlockNum, SIZEOF(wireData->refBlockNum));

		ctx->refBlockPrefix = u4be_read(wireData->refBlockPrefix);
		sha_256_append(&ctx->hashContext, (uint8_t *)&ctx->refBlockPrefix, sizeof(ctx->expiration));

		uint8_t buf[4]; //max_net_usage_words, max_cpu_usage_ms, delay_sec, context_free_actions
		explicit_bzero(buf, sizeof(buf)); //SIZEOF does no work for 4
		sha_256_append(&ctx->hashContext, buf, sizeof(buf));
	}

	security_policy_t policy = policyForSignTxHeader();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_HEADER_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleHeader_ui_runStep();
}

// ============================== ACTION HEADER ==============================

enum {
	HANDLE_ACTION_HEADER_STEP_SHOW_TYPE = 300,
	HANDLE_ACTION_HEADER_STEP_RESPOND,
	HANDLE_ACTION_HEADER_STEP_INVALID,
};

static void signTx_handleActionHeader_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleActionHeader_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_ACTION_HEADER_STEP_SHOW_TYPE) {
		switch(ctx->action_type) {
#	define  CASE(ACTION, STRING) case ACTION: {ui_displayPaginatedText("Action", STRING, this_fn); break;}
			CASE(ACTION_TYPE_TRNSFIOPUBKY, "Transfer FIO tokens");
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	UI_STEP(HANDLE_ACTION_HEADER_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}

	UI_STEP_END(HANDLE_ACTION_HEADER_STEP_INVALID);
}

__noinline_due_to_stack__
void signTx_handleActionHeaderAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_ACTION_HEADER);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t contractAccountName[CONTRACT_ACCOUNT_NAME_LENGTH];
		}* wireData = (void*) wireDataBuffer;

		VALIDATE(SIZEOF(*wireData) == wireDataSize, ERR_INVALID_DATA);

		uint8_t buf[1];
		buf[0] = 1;
		sha_256_append(&ctx->hashContext, buf, SIZEOF(buf)); //one action
		sha_256_append(&ctx->hashContext, (uint8_t *) wireData, SIZEOF(*wireData));

		ctx->action_type = getActionTypeByContractAccountName(ctx->network, wireData->contractAccountName,
		                   CONTRACT_ACCOUNT_NAME_LENGTH);
		TRACE("Action type %d:", ctx->action_type);
	}

	security_policy_t policy = policyForSignTxActionHeader(ctx->action_type);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_ACTION_HEADER_STEP_SHOW_TYPE);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleActionHeader_ui_runStep();
}

// ============================== ACTION AUTHORIZATION ==============================

enum {
	HANDLE_ACTION_AUTHORIZATION_STEP_SHOW_ACTOR = 400,
	HANDLE_ACTION_AUTHORIZATION_STEP_SHOW_PERMISSION,
	HANDLE_ACTION_AUTHORIZATION_STEP_RESPOND,
	HANDLE_ACTION_AUTHORIZATION_STEP_INVALID,
};

static void signTx_handleActionAuthorization_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleActionAuthorization_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

/*	UI_STEP(HANDLE_ACTION_AUTHORIZATION_STEP_SHOW_ACTOR) {
		ui_displayPaginatedText(
		        "Actor",
		        ctx->actionValidationActor,
		        this_fn
		);
	}

	UI_STEP(HANDLE_ACTION_AUTHORIZATION_STEP_SHOW_PERMISSION) {
		ui_displayPaginatedText(
		        "Permission",
		        ctx->actionValidationPermission,
		        this_fn
		);
	}*/

	UI_STEP(HANDLE_ACTION_AUTHORIZATION_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}

	UI_STEP_END(HANDLE_ACTION_AUTHORIZATION_STEP_INVALID);
}

__noinline_due_to_stack__
void signTx_handleActionAuthorizationAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_ACTION_AUTHORIZATION);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t actor[NAME_VAR_LENGTH];
			uint8_t permission[NAME_VAR_LENGTH];
		}* wireData = (void*) wireDataBuffer;

		VALIDATE(SIZEOF(*wireData) == wireDataSize, ERR_INVALID_DATA);

		uint8_t buf[1];
		buf[0] = 1;
		sha_256_append(&ctx->hashContext, buf, SIZEOF(buf)); //one authorization
		sha_256_append(&ctx->hashContext, wireData->actor, SIZEOF(wireData->actor));
		sha_256_append(&ctx->hashContext, wireData->permission, SIZEOF(wireData->permission));

		uint8array_name_to_string(wireData->actor, NAME_VAR_LENGTH, ctx->actionValidationActor, NAME_STRING_MAX_LENGTH);
		uint8array_name_to_string(wireData->permission, NAME_VAR_LENGTH, ctx->actionValidationPermission, NAME_STRING_MAX_LENGTH);
	}

	security_policy_t policy = policyForSignTxActionAuthorization();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_ACTION_AUTHORIZATION_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleActionAuthorization_ui_runStep();
}

// ============================== ACTION DATA ==============================

enum {
	HANDLE_ACTION_DATA_STEP_SHOW_PUBKEY = 400,
	HANDLE_ACTION_DATA_STEP_SHOW_AMOUNT,
	HANDLE_ACTION_DATA_STEP_SHOW_MAX_FEE,
	HANDLE_ACTION_DATA_STEP_SHOW_TPID,
	HANDLE_ACTION_DATA_STEP_RESPOND,
	HANDLE_ACTION_DATA_STEP_INVALID,
};

static void signTx_handleActionData_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleActionData_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_ACTION_DATA_STEP_SHOW_PUBKEY) {
		ui_displayPaginatedText(
		        "Payee Pubkey",
		        ctx->pubkey,
		        this_fn
		);
	}

	UI_STEP(HANDLE_ACTION_DATA_STEP_SHOW_AMOUNT) {
		ui_displayFIOAmountScreen(
		        "Amount",
		        ctx->amount,
		        this_fn
		);
	}

	UI_STEP(HANDLE_ACTION_DATA_STEP_SHOW_MAX_FEE) {
		ui_displayFIOAmountScreen(
		        "Max fee",
		        ctx->maxFee,
		        this_fn
		);
	}

/*	UI_STEP(HANDLE_ACTION_DATA_STEP_SHOW_TPID) {
		ui_displayPaginatedText(
		        "Tpid",
		        ctx->tpid,
		        this_fn
		);
	}*/

	UI_STEP(HANDLE_ACTION_DATA_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}

	UI_STEP_END(HANDLE_ACTION_DATA_STEP_INVALID);
}

__noinline_due_to_stack__
void signTx_handleActionDataAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_ACTION_DATA);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t dataLength[1];
			uint8_t pubkeyLength[1];
			uint8_t pubkey[MAX_WIF_PUBKEY_LENGTH]; // null terminated, for convenience, we will use displayPaginatedText
		}* wireData1 = (void*) wireDataBuffer;
		const uint8_t expectedWireData1Length = SIZEOF(*wireData1) - MAX_WIF_PUBKEY_LENGTH + wireData1->pubkeyLength[0] + 1;

		struct {
			uint8_t amount[8];
			uint8_t maxFee[8];
			uint8_t actor[NAME_VAR_LENGTH];
			uint8_t tpidLength[1];
			uint8_t tpid[MAX_TPID_LENGTH]; // null terminated, for convenience, we will use displayPaginatedText
		}* wireData2 = ((void*) wireDataBuffer) + expectedWireData1Length; 
		const uint8_t expectedWireData2Length = SIZEOF(*wireData2) - MAX_TPID_LENGTH + wireData2->tpidLength[0] + 1;

		VALIDATE(expectedWireData1Length + expectedWireData2Length == wireDataSize, ERR_INVALID_DATA);
		VALIDATE(wireData1->dataLength[0] == wireDataSize - 3, ERR_INVALID_DATA); //-1 for data length, -2 fo trailing 0's
		VALIDATE(wireData1->dataLength[0] <= MAX_SINGLE_BYTE_LENGTH, ERR_INVALID_DATA);
		VALIDATE(wireData1->pubkeyLength[0] < MAX_SINGLE_BYTE_LENGTH, ERR_INVALID_DATA); // < for terminating 0
		VALIDATE(wireData1->pubkeyLength[0] < MAX_WIF_PUBKEY_LENGTH, ERR_INVALID_DATA); // < for terminating 0
		str_validateNullTerminatedTextBuffer(wireData1->pubkey, wireData1->pubkeyLength[0]);

		VALIDATE(wireData2->tpidLength[0] < MAX_SINGLE_BYTE_LENGTH, ERR_INVALID_DATA); // < for terminating 0
		VALIDATE(wireData2->tpidLength[0] < MAX_TPID_LENGTH, ERR_INVALID_DATA); // < for terminating 0
		str_validateNullTerminatedTextBuffer(wireData2->tpid, wireData2->tpidLength[0]);

		ctx -> pubkey = (char *) wireData1->pubkey;
		ctx -> amount = u8be_read(wireData2->amount);
		ctx -> maxFee = u8be_read(wireData2->maxFee);
		uint8array_name_to_string(wireData2->actor, SIZEOF(wireData2->actor), ctx->actionDataActor, NAME_STRING_MAX_LENGTH);
		ctx -> tpid = (char *) wireData2->tpid;


		sha_256_append(&ctx->hashContext, (uint8_t *) wireData1->dataLength, SIZEOF(wireData1->dataLength));
		sha_256_append(&ctx->hashContext, (uint8_t *) wireData1->pubkeyLength, SIZEOF(wireData1->pubkeyLength));
		sha_256_append(&ctx->hashContext, (uint8_t *) wireData1->pubkey, wireData1->pubkeyLength[0]);

		sha_256_append(&ctx->hashContext, (uint8_t *) &ctx->amount, SIZEOF(ctx->amount));
		sha_256_append(&ctx->hashContext, (uint8_t *) &ctx->maxFee, SIZEOF(ctx->maxFee));
		sha_256_append(&ctx->hashContext, (uint8_t *) wireData2->actor, SIZEOF(wireData2->actor));
		sha_256_append(&ctx->hashContext, (uint8_t *) wireData2->tpidLength, SIZEOF(wireData2->tpidLength));
		sha_256_append(&ctx->hashContext, (uint8_t *) wireData2->tpid, wireData2->tpidLength[0]);
	}

	security_policy_t policy = policyForSignTxActionData(ctx->actionValidationActor, ctx->actionDataActor);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_ACTION_DATA_STEP_SHOW_PUBKEY);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleActionData_ui_runStep();
}

// ============================== WITNESS ==============================

enum {
	HANDLE_WITNESS_STEP_DISPLAY_DETAILS = 1000,
	HANDLE_WITNESS_STEP_CONFIRM,
	HANDLE_WITNESS_STEP_RESPOND,
	HANDLE_WITNESS_STEP_INVALID,
} ;

static void signTx_handleWitness_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleWitness_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_WITNESS_STEP_DISPLAY_DETAILS) {
		ui_displayPubkeyScreen("Sign with", &ctx->wittnessPathPubkey, this_fn);
	}

	UI_STEP(HANDLE_WITNESS_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Sign",
		        "transaction?",
		        this_fn,
		        respond_with_user_reject
		);
	}

	UI_STEP(HANDLE_WITNESS_STEP_RESPOND) {
		io_send_buf(SUCCESS, G_io_apdu_buffer, 65 + 32);
		ui_displayBusy(); // needs to happen after I/O
		advanceStage();
	}

	UI_STEP_END(HANDLE_WITNESS_STEP_INVALID);
}

__noinline_due_to_stack__
void signTx_handleWitnessAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_WITNESS);
		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	explicit_bzero(&ctx->wittnessPath, SIZEOF(ctx->wittnessPath));

	{
		// parse
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		size_t parsedSize = bip44_parseFromWire(&ctx->wittnessPath, wireDataBuffer, wireDataSize);
		VALIDATE(parsedSize == wireDataSize, ERR_INVALID_DATA);
	}

	security_policy_t policy = POLICY_DENY;
	{
		// get policy
		policy = policyForSignTxWitness(&ctx->wittnessPath);
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);
	}

	//Extension points
	uint8_t buf[1];
	explicit_bzero(buf, SIZEOF(buf));
	sha_256_append(&ctx->hashContext, buf, SIZEOF(buf));

	//We finish the hash appending a 32-byte empty buffer
	uint8_t hashBuf[32];
	explicit_bzero(hashBuf, SIZEOF(hashBuf));
	sha_256_append(&ctx->hashContext, hashBuf, SIZEOF(hashBuf));

	//we get the resulting hash
	sha_256_finalize(&ctx->hashContext, hashBuf, SIZEOF(hashBuf));
	TRACE("SHA_256_finalize, resulting hash:");
	TRACE_BUFFER(hashBuf, 32);

	//We derive the private key
	private_key_t privateKey;
	derivePrivateKey(&ctx->wittnessPath, &privateKey);
	TRACE("privateKey.d:");
	TRACE_BUFFER(privateKey.d, privateKey.d_len);

	//We want to show pubkey, thus we derive it
	derivePublicKey(&ctx->wittnessPath, &ctx->wittnessPathPubkey);
	TRACE_BUFFER(ctx->wittnessPathPubkey.W, SIZEOF(ctx->wittnessPathPubkey.W));

	//We sign the hash
	//Code producing signatures is taken from EOS app
	uint32_t tx = 0;
	uint8_t V[33];
	uint8_t K[32];
	int tries = 0;

	// Loop until a candidate matching the canonical signature is found
	// Taken from EOS app
	// We use G_io_apdu_buffer to save memory (and also to minimize changes to EOS code)
	// The code produces the signature right where we need it for the respons
	BEGIN_TRY {
		TRY {
			explicit_bzero(G_io_apdu_buffer, SIZEOF(G_io_apdu_buffer));
			for (;;)
			{
				if (tries == 0) {
					rng_rfc6979(G_io_apdu_buffer + 100, hashBuf, privateKey.d, privateKey.d_len, SECP256K1_N, 32, V, K);
				} else {
					rng_rfc6979(G_io_apdu_buffer + 100, hashBuf, NULL, 0, SECP256K1_N, 32, V, K);
				}
				uint32_t infos;
				tx = cx_ecdsa_sign(&privateKey, CX_NO_CANONICAL | CX_RND_PROVIDED | CX_LAST, CX_SHA256,
				                   hashBuf, 32,
				                   G_io_apdu_buffer + 100, 100,
				                   &infos);
				TRACE_BUFFER(G_io_apdu_buffer + 100, 100);

				if ((infos & CX_ECCINFO_PARITY_ODD) != 0) {
					G_io_apdu_buffer[100] |= 0x01;
				}
				G_io_apdu_buffer[0] = 27 + 4 + (G_io_apdu_buffer[100] & 0x01);
				ecdsa_der_to_sig(G_io_apdu_buffer + 100, G_io_apdu_buffer + 1);
				TRACE_BUFFER(G_io_apdu_buffer, 65);

				if (check_canonical(G_io_apdu_buffer + 1)) {
					tx = 1 + 64;
					break;
				} else {
					TRACE("Try %d unsuccesfull! We will not get correct signature!!!!!!!!!!!!!!!!!!!!!!!!!", tries);
					tries++;
				}
			}
		}
		FINALLY {
			memset(&privateKey, 0, sizeof(privateKey));
		}
	}
	END_TRY;

	//We add hash to the response
	TRACE("ecdsa_der_to_sig_result:");
	TRACE_BUFFER(G_io_apdu_buffer, 65);
	memcpy(G_io_apdu_buffer + 65, hashBuf, 32);

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_WITNESS_STEP_DISPLAY_DETAILS);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleWitness_ui_runStep();
}


// ============================== MAIN HANDLER ==============================

typedef void subhandler_fn_t(uint8_t p2, uint8_t* dataBuffer, size_t dataSize);

static subhandler_fn_t* lookup_subhandler(uint8_t p1)
{
	switch(p1) {
#	define  CASE(P1, HANDLER) case P1: return HANDLER;
#	define  DEFAULT(HANDLER)  default: return HANDLER;
		CASE(0x01, signTx_handleInitAPDU);
		CASE(0x02, signTx_handleHeaderAPDU);
		CASE(0x03, signTx_handleActionHeaderAPDU);
		CASE(0x04, signTx_handleActionAuthorizationAPDU);
		CASE(0x05, signTx_handleActionDataAPDU);
		CASE(0x10, signTx_handleWitnessAPDU);
		DEFAULT(NULL)
#	undef   CASE
#	undef   DEFAULT
	}
}

void signTransaction_handleAPDU(
        uint8_t p1,
        uint8_t p2,
        uint8_t* wireDataBuffer,
        size_t wireDataSize,
        bool isNewCall
)
{
	TRACE("P1 = 0x%x, P2 = 0x%x, isNewCall = %d", p1, p2, isNewCall);

	if (isNewCall) {
		explicit_bzero(ctx, SIZEOF(*ctx));
		ctx->stage = SIGN_STAGE_INIT;
	}

	subhandler_fn_t* subhandler = lookup_subhandler(p1);
	VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
	subhandler(p2, wireDataBuffer, wireDataSize);
}

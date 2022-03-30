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
#include "testUtils.h"

#define HD HARDENED_BIP32

static void pathSpec_init(bip44_path_t* pathSpec, const uint32_t* pathArray, uint32_t pathLength)
{
	pathSpec->length = pathLength;
	memmove(pathSpec->path, pathArray, pathLength * 4);
}


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
/*	BEGIN_ASSERT_NOEXCEPT {
		PRINTF("Running tests\n");
		run_hex_test();
		run_endian_test();
		run_textUtils_test();
		run_bip44_test();
		run_key_derivation_test();
		PRINTF("All tests done\n");
	} END_ASSERT_NOEXCEPT;*/

	cx_err_t err;
    uint8_t outBuffer[204];

BEGIN_ASSERT_NOEXCEPT {

	//initializing derivation paths
    uint32_t path1[] = {HD + 44, HD + 235, HD + 0, 0, 0};
	bip44_path_t pathSpec1;
	pathSpec_init(&pathSpec1, path1, 5);
	bip44_PRINTF(&pathSpec1);
	PRINTF("\n");

    uint32_t path2[] = {HD + 44, HD + 235, HD + 0, 0, 2000};
	bip44_path_t pathSpec2;
	pathSpec_init(&pathSpec2, path2, 5);
	bip44_PRINTF(&pathSpec2);
	PRINTF("\n");


	//computing private keys
	private_key_t privateKey1;
	derivePrivateKey(&pathSpec1, &privateKey1);
	TRACE("%d", SIZEOF(privateKey1.d));
	TRACE_BUFFER(privateKey1.d, SIZEOF(privateKey1.d));
	const char* expectedPrivateHex1 = "4d597899db76e87933e7c6841c2d661810f070bad20487ef20eb84e182695a3a";

	private_key_t privateKey2;
	derivePrivateKey(&pathSpec2, &privateKey2);
	TRACE("%d", SIZEOF(privateKey2.d));
	TRACE_BUFFER(privateKey2.d, SIZEOF(privateKey2.d));
	const char* expectedPrivateHex2 = "0762d870ba3a00625d02c8374dbcd33f1df4d8f1abbaa89387ab5c8afa533d90";

	uint8_t expectedPrivate[32];

	size_t expectedSize = decode_hex(expectedPrivateHex1, expectedPrivate, SIZEOF(expectedPrivate));
	TRACE("%d", SIZEOF(expectedPrivate));
	TRACE_BUFFER(expectedPrivate, SIZEOF(expectedPrivate));
	EXPECT_EQ_BYTES(expectedPrivate, privateKey1.d, expectedSize);

	expectedSize = decode_hex(expectedPrivateHex2, expectedPrivate, SIZEOF(expectedPrivate));
	TRACE("%d", SIZEOF(expectedPrivate));
	TRACE_BUFFER(expectedPrivate, SIZEOF(expectedPrivate));
	EXPECT_EQ_BYTES(expectedPrivate, privateKey2.d, expectedSize);


	//computing public keys
	public_key_t publicKey1;
	derivePublicKey(&pathSpec1, &publicKey1);
	TRACE("%d", SIZEOF(publicKey1.W));
	TRACE_BUFFER(publicKey1.W, SIZEOF(publicKey1.W));
	const char* expectedPublicHex1 = "04a9a222bc3b1a5a58ada17d10069b3961ebd0f917d4b2106031a061915ca9cc24a06941e0a4c0d5e266850ff980ad349ab8b027c93bf4aead1984168ad43e30ab";

	public_key_t publicKey2;
	derivePublicKey(&pathSpec2, &publicKey2);
	TRACE("%d", SIZEOF(publicKey2.W));
	TRACE_BUFFER(publicKey2.W, SIZEOF(publicKey2.W));
	const char* expectedPublicHex2 = "0484e52dfea57b8f1787488a356374cd8e8515b8ad8db3dd4f9088d8e42ed2fb6d571e8894cccbdbf15e1bd84f8b4362f52d1b5b712b9775c0a51cdd5ee9a9e8ca";

	uint8_t expectedPublic1[65];
	decode_hex(expectedPublicHex1, expectedPublic1, SIZEOF(expectedPublic1));
	TRACE("%d", SIZEOF(expectedPublic1));
	TRACE_BUFFER(expectedPublic1, SIZEOF(expectedPublic1));
	EXPECT_EQ_BYTES(expectedPublic1, publicKey1.W, SIZEOF(expectedPublic1));

	uint8_t expectedPublic2[65];
	decode_hex(expectedPublicHex2, expectedPublic2, SIZEOF(expectedPublic2));
	TRACE("%d", SIZEOF(expectedPublic2));
	TRACE_BUFFER(expectedPublic2, SIZEOF(expectedPublic2));
	EXPECT_EQ_BYTES(expectedPublic2, publicKey2.W, SIZEOF(expectedPublic2));


	//computing shared secret
	unsigned char basicSecret[32];
    explicit_bzero(basicSecret, SIZEOF(basicSecret));
	unsigned char secret[SHA_512_SIZE];
	
	cx_ecdh_no_throw(&privateKey1, CX_ECDH_X, publicKey2.W, publicKey2.W_len, basicSecret, SIZEOF(basicSecret));
	sha_512_hash(basicSecret, SIZEOF(basicSecret), secret, SIZEOF(secret));

	uint8_t expectedSecret[SHA_512_SIZE];
	const char* expectedSecretHex = "66af974c1553e8f5702dfceef4f6ba317bd058e5d2188dfd15653ad2d445f53d5aedea242df20682eae2d7edda9bbaba39a8dbe672bcf015bdf63e90e9826672";
    decode_hex(expectedSecretHex, expectedSecret, SIZEOF(expectedSecret));
	EXPECT_EQ_BYTES(expectedSecret, secret, SIZEOF(expectedSecret));

	//Computing K
	uint8_t K[SHA_512_SIZE];
	sha_512_hash(secret, SIZEOF(secret), K, SIZEOF(K));

	uint8_t expectedK[SHA_512_SIZE];
	const char* expectedKHex = "839c90327d2635ffaa77af093b7b1536d34953d7900ca818ad577f0dccc250aeb4be8e3e34e322c9c308a7351e85bd266d5e4f5f6d160a7255f4a4bebfae848c";
    decode_hex(expectedKHex, expectedK, SIZEOF(expectedK));
	EXPECT_EQ_BYTES(expectedK, K, SIZEOF(expectedK));

	//Setting IV and msg
	const char * IVHex = "f300888ca4f512cebdc0020ff0f7224c";
	uint8_t IV[16];
    decode_hex(IVHex, IV, SIZEOF(IV));

	//0x10 at the end is padding ... coresponds to what fiojs does
	const char * msg1Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef10101010101010101010101010101010";
	uint8_t msg1[96+16];
    decode_hex(msg1Hex, msg1, SIZEOF(msg1));

	//aes-256-cbc
	cx_aes_key_t aesKey;
    cx_aes_init_key_no_throw(K, 32, &aesKey);
	uint8_t out[200];
    explicit_bzero(out, SIZEOF(out));
	size_t outLen = SIZEOF(out);
	err = cx_aes_iv_no_throw(&aesKey, CX_ENCRYPT | CX_CHAIN_CBC | CX_PAD_NONE | CX_LAST, IV, SIZEOF(IV), msg1, SIZEOF(msg1), out, &outLen);


	memmove(outBuffer + sizeof(err), out, SIZEOF(outBuffer) - sizeof(err));
	memmove(outBuffer, (uint8_t *)(&err), sizeof(err));


} END_ASSERT_NOEXCEPT;

	io_send_buf(SUCCESS, outBuffer, sizeof(outBuffer));
	ui_idle();
}

#endif // DEVEL

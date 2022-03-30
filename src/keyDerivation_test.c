#ifdef DEVEL

#include "keyDerivation.h"
#include "hexUtils.h"
#include "testUtils.h"
#include "utils.h"

/*static void pathSpec_init(bip44_path_t* pathSpec, const uint32_t* pathArray, uint32_t pathLength)
{
	pathSpec->length = pathLength;
	memmove(pathSpec->path, pathArray, pathLength * 4);
}

void testcase_derivePrivateKey(uint32_t* path, uint32_t pathLen, const char* expectedHex)
{
	PRINTF("testcase_derivePrivateKey ");

	bip44_path_t pathSpec;
	pathSpec_init(&pathSpec, path, pathLen);
	bip44_PRINTF(&pathSpec);
	PRINTF("\n");


	private_key_t privateKey;
	derivePrivateKey(&pathSpec, &privateKey);
	TRACE("%d", SIZEOF(privateKey.d));
	TRACE_BUFFER(privateKey.d, SIZEOF(privateKey.d));

	uint8_t expected[32];
	size_t expectedSize = decode_hex(expectedHex, expected, SIZEOF(expected));
	TRACE("%d", SIZEOF(expected));
	TRACE_BUFFER(expected, SIZEOF(expected));

	EXPECT_EQ_BYTES(expected, privateKey.d, expectedSize);
}

void testPrivateKeyDerivation()
{

#define HD HARDENED_BIP32

#define TESTCASE(path_, expectedHex_) \
	{ \
		uint32_t path[] = { UNWRAP path_ }; \
		testcase_derivePrivateKey(path, ARRAY_LEN(path), expectedHex_); \
	}


	// Note: Failing tests here? Did you load testing mnemonic
	// "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"?

	TESTCASE(
	        (HD + 44, HD + 235, HD + 0, 0, 0),

	        "4d597899db76e87933e7c6841c2d661810f070bad20487ef20eb84e182695a3a"
	);

	TESTCASE(
	        (HD + 44, HD + 235, HD + 0, 0, 2000 ),

	        "0762d870ba3a00625d02c8374dbcd33f1df4d8f1abbaa89387ab5c8afa533d90"
	);
#undef TESTCASE

#define TESTCASE(path_, error_) \
	{ \
		uint32_t path[] = { UNWRAP path_ }; \
		EXPECT_THROWS(testcase_derivePrivateKey(path, ARRAY_LEN(path), ""), error_ ); \
	}

	TESTCASE( (HD + 43, HD + 235, HD + 0, 0), ERR_REJECTED_BY_POLICY);
	TESTCASE( (HD + 44, 235, HD + 1, 0, 0), ERR_REJECTED_BY_POLICY);
	TESTCASE( (HD + 44, HD + 234, HD + 1, 0, 0), ERR_REJECTED_BY_POLICY);
	TESTCASE( (HD + 44, HD + 235, HD + 1, 0, 0, 0), ERR_REJECTED_BY_POLICY);
#undef TESTCASE
}

void testcase_derivePublicKey(uint32_t* path, uint32_t pathLen, const char* expectedHex)
{
	PRINTF("testcase_derivePublicKey ");

	bip44_path_t pathSpec;
	pathSpec_init(&pathSpec, path, pathLen);
	bip44_PRINTF(&pathSpec);
	PRINTF("\n");

	public_key_t publicKey;
	derivePublicKey(&pathSpec, &publicKey);
	TRACE("%d", SIZEOF(publicKey.W));
	TRACE_BUFFER(publicKey.W, SIZEOF(publicKey.W));

	uint8_t expected[65];
	decode_hex(expectedHex, expected, SIZEOF(expected));
	TRACE("%d", SIZEOF(expected));
	TRACE_BUFFER(expected, SIZEOF(expected));

	EXPECT_EQ_BYTES(expected, publicKey.W, SIZEOF(expected));
}

void testPublicKeyDerivation()
{
#define TESTCASE(path_, expectedHex_) \
	{ \
		uint32_t path[] = { UNWRAP path_ }; \
		testcase_derivePublicKey(path, ARRAY_LEN(path), expectedHex_); \
	}


	TESTCASE(
	        (HD + 44, HD + 235, HD + 0, 0, 0),
	        "04a9a222bc3b1a5a58ada17d10069b3961ebd0f917d4b2106031a061915ca9cc24a06941e0a4c0d5e266850ff980ad349ab8b027c93bf4aead1984168ad43e30ab"
	)

	TESTCASE(
	        (HD + 44, HD + 235, HD + 0, 0, 2000),
	        "0484e52dfea57b8f1787488a356374cd8e8515b8ad8db3dd4f9088d8e42ed2fb6d571e8894cccbdbf15e1bd84f8b4362f52d1b5b712b9775c0a51cdd5ee9a9e8ca"
	);


#undef TESTCASE
}


void testDHEncryption() {
	PRINTF("testcase_derivePrivateKey ");

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


	unsigned char secret[64];
	uint8_t expectedSecret[64];
	int secretLength = cx_ecdh(&privateKey1, CX_ECDH_POINT, expectedPublic2, SIZEOF(expectedPublic2), secret, SIZEOF(secret));
	io_send_buf(SUCCESS, secret, 64);

//	ASSERT(secretLength == 64);

//	const char* expectedSecretHex = "66af974c1553e8f5702dfceef4f6ba317bd058e5d2188dfd15653ad2d445f53d5aedea242df20682eae2d7edda9bbaba39a8dbe672bcf015bdf63e90e9826672";
//	decode_hex(expectedSecretHex, expectedSecret, SIZEOF(expectedSecret));
//	EXPECT_EQ_BYTES(expectedSecret, secret, SIZEOF(expectedSecret));
}

void run_key_derivation_test()
{
	PRINTF("Running key derivation tests\n");
	PRINTF("If they fail, make sure you seeded your device with\n");
	PRINTF("12-word mnemonic: 11*abandon about\n");
//	testPrivateKeyDerivation();
//	testPublicKeyDerivation();
    testDHEncryption();
}*/

#endif // DEVEL

#include "fio.h"

network_type_t getNetworkByChainId(uint8_t *chainId, size_t length)
{
	ASSERT(length == CHAIN_ID_LENGTH);
	const uint8_t testnetId[CHAIN_ID_LENGTH] = {0xb2, 0x09, 0x01, 0x38, 0x0a, 0xf4, 0x4e, 0xf5,
	                                            0x9c, 0x59, 0x18, 0x43, 0x9a, 0x1f, 0x9a, 0x41,
	                                            0xd8, 0x36, 0x69, 0x02, 0x03, 0x19, 0xa8, 0x05,
	                                            0x74, 0xb8, 0x04, 0xa5, 0xf9, 0x5c, 0xbd, 0x7e
	                                           };
	if (!memcmp(chainId, testnetId, CHAIN_ID_LENGTH)) {
		return NETWORK_TESTNET;
	}

	const uint8_t mainnetId[CHAIN_ID_LENGTH] = {0x21, 0xdc, 0xae, 0x42, 0xc0, 0x18, 0x22, 0x00,
	                                            0xe9, 0x3f, 0x95, 0x4a, 0x07, 0x40, 0x11, 0xf9,
	                                            0x04, 0x8a, 0x76, 0x24, 0xc6, 0xfe, 0x81, 0xd3,
	                                            0xc9, 0x54, 0x1a, 0x61, 0x4a, 0x88, 0xbd, 0x1c
	                                           };
	if (!memcmp(chainId, mainnetId, CHAIN_ID_LENGTH)) {
		return NETWORK_MAINNET;
	}

	return NETWORK_UNKNOWN;
}

action_type_t getActionTypeByContractAccountName(network_type_t network, uint8_t * contractAccountName, size_t length)
{
	ASSERT(length == CONTRACT_ACCOUNT_NAME_LENGTH);
	const uint8_t trnsfiopubky[CONTRACT_ACCOUNT_NAME_LENGTH] = {0x00, 0x00, 0x98, 0x0a, 0xd2, 0x0c, 0xa8, 0x5b,
	                                                            0xe0, 0xe1, 0xd1, 0x95, 0xba, 0x85, 0xe7, 0xcd
	                                                           };
	if (network == NETWORK_TESTNET || network == NETWORK_MAINNET) {
		if (!memcmp(contractAccountName, trnsfiopubky, CONTRACT_ACCOUNT_NAME_LENGTH)) {
			return ACTION_TYPE_TRNSFIOPUBKY;
		}
		return ACTION_TYPE_UNKNOWN;
	}

	return ACTION_TYPE_UNKNOWN;
}


static const char* charmap = ".12345abcdefghijklmnopqrstuvwxyz";

// From EOS app, slightly modified
void name_to_string(name_t value, char *out, size_t size)
{

	uint32_t i = 0;
	uint64_t tmp = value;

	uint32_t actual_size = 13;
	char str[13] = {'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'};

	for (i = 0; i <= 12; ++i) {
		uint8_t index = tmp & (i == 0 ? 0x0f : 0x1f);
		ASSERT(index < strlen(charmap));
		char c = charmap[index];
		str[12 - i] = c;
		tmp >>= (i == 0 ? 4 : 5);
	}

	while (actual_size != 0 && str[actual_size - 1] == '.') {
		actual_size--;
	}

	ASSERT(actual_size + 1 < size);
	memcpy(out, str, actual_size);
	out[actual_size] = 0;
}

// Wrapper
void uint8array_name_to_string(uint8_t *value, size_t valueSize, char *out, size_t outSize)
{
	ASSERT(valueSize == NAME_VAR_LENGTH);
	name_t tmp;
	ASSERT(sizeof(tmp) >= valueSize);
	memcpy(&tmp, value, valueSize);
	name_to_string(tmp, out, outSize);
}


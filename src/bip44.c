#include "common.h"
#include "bip44.h"
#include "endian.h"

static const uint32_t MAX_REASONABLE_ADDRESS = 1000;

size_t bip44_parseFromWire(
        bip44_path_t* pathSpec,
        const uint8_t *dataBuffer, size_t dataSize
)
{
	// Ensure we have length
	VALIDATE(dataSize >= 1, ERR_INVALID_DATA);

	// Cast length to size_t
	size_t length = dataBuffer[0];

	// Ensure length is valid
	VALIDATE(length <= ARRAY_LEN(pathSpec->path), ERR_INVALID_DATA);
	VALIDATE(length * 4 + 1 <= dataSize, ERR_INVALID_DATA);

	pathSpec->length = length;

	size_t offset = 1;
	for (size_t i = 0; i < length; i++) {
		pathSpec->path[i] = u4be_read(dataBuffer + offset);
		offset += 4;
	}
	return offset;
}

bool isHardened(uint32_t value)
{
	return value == (value | HARDENED_BIP32);
}

uint32_t unharden(uint32_t value)
{
	ASSERT(isHardened(value));
	return value & (~HARDENED_BIP32);
}

// FIO: /44'/235'
bool bip44_hasValidFIOPrefix(const bip44_path_t* pathSpec)
{
#define CHECK(cond) if (!(cond)) return false
	CHECK(pathSpec->length > BIP44_I_COIN_TYPE);
	CHECK(pathSpec->path[BIP44_I_PURPOSE] == (PURPOSE_FIO | HARDENED_BIP32));
	CHECK(pathSpec->path[BIP44_I_COIN_TYPE] == (COIN_TYPE_FIO | HARDENED_BIP32));
	CHECK(pathSpec->path[BIP44_I_ACCOUNT] == (0 | HARDENED_BIP32));
	CHECK(pathSpec->path[BIP44_I_CHAIN] == (0));
	return true;
#undef CHECK
}

// Address

bool bip44_containsAddress(const bip44_path_t* pathSpec)
{
	return pathSpec->length > BIP44_I_ADDRESS;
}

uint32_t bip44_getAddressValue(const bip44_path_t* pathSpec)
{
	ASSERT(pathSpec->length > BIP44_I_ADDRESS);
	return pathSpec->path[BIP44_I_ADDRESS];
}

bool bip44_hasReasonableAddress(const bip44_path_t* pathSpec)
{
	if (!bip44_containsAddress(pathSpec)) return false;
	const uint32_t address = bip44_getAddressValue(pathSpec);
	return (address <= MAX_REASONABLE_ADDRESS);
}

// Further
bool bip44_containsMoreThanAddress(const bip44_path_t* pathSpec)
{
	return (pathSpec->length > BIP44_I_ADDRESS + 1);
}

// returns the length of the resulting string
size_t bip44_printToStr(const bip44_path_t* pathSpec, char* out, size_t outSize)
{
	ASSERT(outSize < BUFFER_SIZE_PARANOIA);
	// We have to have space for terminating null
	ASSERT(outSize > 0);
	char* ptr = out;
	char* end = (out + outSize);

#define WRITE(fmt, ...) \
	{ \
		ASSERT(ptr <= end); \
		STATIC_ASSERT(sizeof(end - ptr) == sizeof(size_t), "bad size_t size"); \
		size_t availableSize = (size_t) (end - ptr); \
		/* Note(ppershing): We do not bother checking return */ \
		/* value of snprintf as it always returns 0. */ \
		/* Go figure out ... */ \
		snprintf(ptr, availableSize, fmt, ##__VA_ARGS__); \
		size_t res = strlen(ptr); \
		/* if snprintf filled all the remaining space, there is no space for '\0', */ \
		/* i.e. outSize is insufficient, we messed something up */ \
		/* usually, outSize >= 1 + BIP44_MAX_PATH_STRING_LENGTH */ \
		ASSERT(res + 1 <= availableSize); \
		ptr += res; \
	}

	WRITE("m");

	ASSERT(pathSpec->length < ARRAY_LEN(pathSpec->path));

	for (size_t i = 0; i < pathSpec->length; i++) {
		const uint32_t value = pathSpec->path[i];

		if ((value & HARDENED_BIP32) == HARDENED_BIP32) {
			WRITE("/%d'", (int) (value & ~HARDENED_BIP32));
		} else {
			WRITE("/%d", (int) value);
		}
	}
#undef WRITE
	ASSERT(ptr < end);
	ASSERT(ptr >= out);

	return ptr - out;
}

#ifdef DEVEL
void bip44_PRINTF(const bip44_path_t* pathSpec)
{
	char tmp[1 + BIP44_MAX_PATH_STRING_LENGTH];
	SIZEOF(*pathSpec);
	bip44_printToStr(pathSpec, tmp, SIZEOF(tmp));
	PRINTF("%s", tmp);
};
#endif // DEVEL

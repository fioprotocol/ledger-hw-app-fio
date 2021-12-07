#include "textUtils.h"
#include "hexUtils.h"

#define WRITE_CHAR(ptr, end, c) \
	{ \
		ASSERT(ptr + 1 <= end); \
		*ptr = (c); \
		ptr++; \
	}

size_t str_formatFIOAmount(uint64_t amount, char* out, size_t outSize)
{
	ASSERT(outSize < BUFFER_SIZE_PARANOIA);

	char scratchBuffer[30];
	char* ptr = BEGIN(scratchBuffer);
	char* end = END(scratchBuffer);

	// We print in reverse

	// decimal digits
	for (int dec = 0; dec < 9; dec++) {
		WRITE_CHAR(ptr, end, '0' + (amount % 10));
		amount /= 10;
	}
	WRITE_CHAR(ptr, end, '.');
	// We want at least one iteration
	int place = 0;
	do {
		// thousands separator
		if (place && (place % 3 == 0)) {
			WRITE_CHAR(ptr, end, ',');
		}
		WRITE_CHAR(ptr, end, '0' + (amount % 10));
		amount /= 10;
		place++;
	} while (amount > 0);

	// Size without terminating character
	STATIC_ASSERT(sizeof(ptr - scratchBuffer) == sizeof(size_t), "bad size_t size");
	size_t rawSize = (size_t) (ptr - scratchBuffer);

	const char *suffix = " FIO";
	const size_t suffixLength = strlen(suffix);

	if (rawSize + suffixLength + 1 > outSize) {
		THROW(ERR_DATA_TOO_LARGE);
	}

	// Copy reversed & append terminator
	for (size_t i = 0; i < rawSize; i++) {
		out[i] = scratchBuffer[rawSize - 1 - i];
	}
	out[rawSize] = 0;

	snprintf(out + rawSize, outSize - rawSize, "%s", suffix);
	ASSERT(strlen(out) == rawSize + suffixLength);

	return rawSize + suffixLength;
}

size_t str_formatUint64(uint64_t number, char* out, size_t outSize)
{
	ASSERT(outSize < BUFFER_SIZE_PARANOIA);

	char scratchBuffer[30];
	char* ptr = BEGIN(scratchBuffer);
	char* end = END(scratchBuffer);

	// We print in reverse
	// We want at least one iteration
	int place = 0;
	do {
		WRITE_CHAR(ptr, end, '0' + (number % 10));
		number /= 10;
		place++;
	} while (number > 0);

	// Size without terminating character
	STATIC_ASSERT(sizeof(ptr - scratchBuffer) == sizeof(size_t), "bad size_t size");
	size_t rawSize = (size_t) (ptr - scratchBuffer);

	if (rawSize + 1 > outSize) {
		THROW(ERR_DATA_TOO_LARGE);
	}

	// Copy reversed & append terminator
	for (size_t i = 0; i < rawSize; i++) {
		out[i] = scratchBuffer[rawSize - 1 - i];
	}
	out[rawSize] = 0;

	ASSERT(strlen(out) == rawSize);

	return rawSize;
}

// check if it is ASCII between 32 and 126
void str_validateTextBuffer(const uint8_t* text, size_t textSize)
{
	ASSERT(textSize < BUFFER_SIZE_PARANOIA);

	for (size_t i = 0; i < textSize; i++) {
		VALIDATE(text[i] <= 126, ERR_INVALID_DATA);
		VALIDATE(text[i] >= 32, ERR_INVALID_DATA);
	}
}

//text[textSize] has to be 0
void str_validateNullTerminatedTextBuffer(const uint8_t* text, size_t textSize)
{
	str_validateTextBuffer(text, textSize);
	VALIDATE(text[textSize] == 0, ERR_INVALID_DATA);
}


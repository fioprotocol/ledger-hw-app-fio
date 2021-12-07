#ifdef DEVEL

#include "common.h"
#include "textUtils.h"
#include "testUtils.h"



void testcase_formatUint64(
        uint64_t number,
        const char* expected
)
{
	PRINTF("testcase_formatUint64 %s\n", expected);

	{
		char tmp[30];
		size_t len = str_formatUint64(number, tmp, SIZEOF(tmp));
		EXPECT_EQ(len, strlen(expected));
		EXPECT_EQ(strcmp(tmp, expected), 0);
	}

	{
		// check for buffer overflows
		char tmp[30];
		EXPECT_THROWS(str_formatUint64(number, tmp, strlen(expected)), ERR_DATA_TOO_LARGE);
	}
}

void test_formatUint64()
{
	testcase_formatUint64( 0, "0");
	testcase_formatUint64( 1, "1");
	testcase_formatUint64( 4924800, "4924800");
	testcase_formatUint64( 4924799, "4924799");
	testcase_formatUint64( -1ll, "18446744073709551615");
}

void run_textUtils_test()
{
	test_formatUint64();
}

#endif // DEVEL

#include "gmock/gmock.h"
#include "cpppcap.h"

using namespace Pcap;

TEST(CppPcap,  findAllDevs) {
   auto devList = findAllDevs();   // this simple test may catch the case when function fails to return a vector
}

int main(int argc, char *argv[])
{
	testing::InitGoogleMock (&argc, argv);
	return RUN_ALL_TESTS();
}

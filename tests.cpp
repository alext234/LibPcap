#include "gmock/gmock.h"
#include "cpppcap.h"
#include <iostream>

using namespace Pcap;

TEST(CppPcap,  findAllDevs) {
   auto devList = findAllDevs();   // this simple test may catch the case when function fails to return a vector
   for (auto it=devList.cbegin(); it!=devList.cend(); ++it){
       std::cout<<*it << std::endl;  
   }
}

int main(int argc, char *argv[])
{
	testing::InitGoogleMock (&argc, argv);
	return RUN_ALL_TESTS();
}

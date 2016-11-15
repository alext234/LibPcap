#include "gmock/gmock.h"
#include "cpppcap.h"
#include <iostream>

using namespace Pcap;


// this test case will get from actual system
TEST(CppPcap,  findAllDevs) {
    auto devList = findAllDevs();   // this simple test may catch the case when function fails to return a vector
    for (auto it=devList.cbegin(); it!=devList.cend(); ++it){
        std::cout<<*(*it) << std::endl;  
    }
}

TEST(CppPcap,  lookUpDev) {
   auto dev = lookUpDev();  
   if (dev!=nullptr) {
       std::cout<<*dev<< std::endl;  
   }
}
#define abc "hello"
TEST(CppPcap, openOfflinePcapFile) {
    std::string pcapFile{SAMPLE_PCAP_DIR};
    pcapFile+="/sample_http.pcap";
    
    
    auto dev = openOffline(pcapFile);
    // TODO: register observer and start loop

}

int main(int argc, char *argv[])
{
	testing::InitGoogleMock (&argc, argv);
	return RUN_ALL_TESTS();
}

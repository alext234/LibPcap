#include "gmock/gmock.h"
#include "cpppcap.h"
#include <iostream>
#include "cpp_observer.h"

using namespace Pcap;
using namespace testing;


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

TEST(CppPcap, openOfflinePcapFileNotExist) {
    try{
        auto dev = openOffline("notExistFile.pcap");
        ASSERT_THAT(true, Eq(false));
     } catch (const Pcap::Error &err) {
        
     }

}

TEST(CppPcap, openOfflinePcapFileObserverObject) {


    struct PacketObserver: public AbstractObserver<Packet> {
        void onNotified(const Packet& packet) override {
            receivedCount +=1;
        }

        int receivedCount=0;

    };

    std::string pcapFile{SAMPLE_PCAP_DIR};
    pcapFile+="sample_http.cap";
    
    
    auto dev = openOffline(pcapFile);
    // register observer 
    auto observer = std::make_shared<PacketObserver>();
    dev->registerObserver(observer);

    
    dev->loop();
    ASSERT_THAT (observer->receivedCount, Gt(0));

}

TEST(CppPcap, openOfflinePcapFileLambda) {


    int receivedCount=0;

    std::string pcapFile{SAMPLE_PCAP_DIR};
    pcapFile+="sample_http.cap";
    
    
    auto dev = openOffline(pcapFile);
    // register observer 
    dev->registerObserver([&receivedCount](const Packet& packet){
        ++receivedCount;
    });

    
    dev->loop();
    ASSERT_THAT (receivedCount, Gt(0));

}

// TODO openOffline but copy packet 

int main(int argc, char *argv[])
{
	testing::InitGoogleMock (&argc, argv);
	return RUN_ALL_TESTS();
}

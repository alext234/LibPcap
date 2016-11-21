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
TEST(CppPcap, openOfflinePcapMultipleFileObserverObject) {


    struct PacketObserver: public AbstractObserver<Packet> {
        void onNotified(const Packet& packet) override {
            receivedCount +=1;            
            packets.push_back (packet);
        }

        int receivedCount=0;
        std::vector<Packet> packets;
        
    };

    std::string pcapFile{SAMPLE_PCAP_DIR};
    pcapFile+="sample_http.cap";
    
    
    auto dev = openOffline(pcapFile);
    // register observer 
    auto observer1 = std::make_shared<PacketObserver>();
    auto observer2 = std::make_shared<PacketObserver>();
    dev->registerObserver(observer1);
    dev->registerObserver(observer2);

    
    dev->loop();
    ASSERT_THAT (observer1->receivedCount, Eq(observer2->receivedCount));

    // make sure packets contents are the same for both receiver
    for (unsigned int i=0; i<observer1->packets.size(); ++i) {
        std::vector<uint8_t>observer1Data = observer1->packets[i].data();
        std::vector<uint8_t>observer2Data = observer2->packets[i].data();
        ASSERT_THAT(observer1Data.size(), Eq(observer2Data.size()));
        
        for (unsigned int j=0; j<observer1Data.size(); ++j) {
            ASSERT_THAT (observer1Data[j], Eq(observer2Data[j]));
        }


    }

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


TEST(CppPcap, openOfflinePcapFileAndWriteToPCap) {

    std::string pcapFile{SAMPLE_PCAP_DIR};
    pcapFile+="sample_http.cap";
    
    
    auto dev = openOffline(pcapFile);

    auto fileDumper = dev->generateFileDumper("output.cap");


    dev->loop(*fileDumper);
    ASSERT_THAT (fileDumper->packetCount(), Gt(uint32_t(0)));
    fileDumper.reset(); // also force close of the file

    // TODO: compare the output file with the original one

}
// TODO: dump to file via observer


int main(int argc, char *argv[])
{
	testing::InitGoogleMock (&argc, argv);
	return RUN_ALL_TESTS();
}

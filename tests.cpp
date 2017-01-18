#include "gmock/gmock.h"
#include "cpppcap.h"
#include <iostream>
#include "cpp_observer.h"

using namespace Pcap;
using namespace testing;

char** g_argv;
int g_argc;

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

TEST(CppPcap, openOfflinePcapFileObserverObjectBreakLoopByCount) {


    enum{COUNT_TO_RECEIVE=5};
    struct PacketObserver: public AbstractObserver<Packet> {
        PacketObserver(std::shared_ptr<Dev> dev) : dev{dev} {}
        void onNotified(const Packet& packet) override {
            receivedCount +=1;
            if (receivedCount==COUNT_TO_RECEIVE){
                dev-> breakLoop();
            }
        }

        int receivedCount=0;
        std::shared_ptr<Dev> dev;

    };

    std::string pcapFile{SAMPLE_PCAP_DIR};
    pcapFile+="sample_http.cap";
    
    
    auto dev = openOffline(pcapFile);
    // register observer 
    auto observer = std::make_shared<PacketObserver>(dev);
    dev->registerObserver(observer);

    
    dev->loop();
    ASSERT_THAT (observer->receivedCount, Eq(COUNT_TO_RECEIVE));

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

bool comparePcapFiles(std::string filename1, std::string filename2) {

    auto dev1 = openOffline(filename1);
    auto dev2 = openOffline(filename2);

    std::vector<Packet> packetlist1, packetlist2;

    dev1->registerObserver([&packetlist1](const Packet& packet){
        packetlist1.push_back(packet);
    });

    dev1->loop();
    dev2->registerObserver([&packetlist2](const Packet& packet){
        packetlist2.push_back(packet);
    });

    dev2->loop();
    
    auto it1= packetlist1.cbegin();
    auto it2= packetlist2.cbegin();
    for (; it1!=packetlist1.cend(); ) {
        if (*it1==*it2){ // compare 2 packets

            ++it1;
            ++it2;
        } else {
            return false;
        }
    }
    return true;
}

TEST(CppPcap, openOfflinePcapFileAndWriteToPCap) {

    std::string pcapFile{SAMPLE_PCAP_DIR};
    pcapFile+="sample_http.cap";
    
    
    auto dev = openOffline(pcapFile);

    auto fileDumper = dev->generateFileDumper("output.cap");


    dev->loop(*fileDumper);
    ASSERT_THAT (fileDumper->packetCount(), Gt(uint32_t(0)));
    fileDumper.reset(); // also force close of the file

    ASSERT_THAT(comparePcapFiles(pcapFile, "output.cap"), Eq(true));

}

TEST(CppPcap, openOfflinePcapFileAndWriteToMultiplePcap) {

    std::string pcapFile{SAMPLE_PCAP_DIR};
    pcapFile+="sample_http.cap";
    
    
    auto dev = openOffline(pcapFile);

    auto fileDumper1 = dev->generateFileDumper("output1.cap");
    auto fileDumper2 = dev->generateFileDumper("output2.cap");


    dev->loop(std::vector<std::shared_ptr<Dumper>>{fileDumper1, fileDumper2});

    ASSERT_THAT (fileDumper1->packetCount(), Gt(uint32_t(0)));
    ASSERT_THAT (fileDumper2->packetCount(), Gt(uint32_t(0)));

    fileDumper1.reset(); 
    fileDumper2.reset(); 

    ASSERT_THAT(comparePcapFiles(pcapFile, "output1.cap"), Eq(true));
    ASSERT_THAT(comparePcapFiles(pcapFile, "output2.cap"), Eq(true));

}

TEST(CppPcap, dumpSelectivelyToFileInObserver) {


    struct PacketObserver: public AbstractObserver<Packet> {
        PacketObserver(Dumper& dumper): _dumper{dumper} {}
        void onNotified(const Packet& packet) override {
            ++receivedCount;
		
            // dumper every other packet
            if (receivedCount%2==0) {
                _dumper.dumpPacket (packet);
                ++dumpCount;
            }

        }

        int receivedCount=0;
        int dumpCount=0;
        Dumper& _dumper;
        

        
    };

    std::string pcapFile{SAMPLE_PCAP_DIR};
    pcapFile+="sample_http.cap";
    
    
    auto dev = openOffline(pcapFile);
    auto fileDumper1 = dev->generateFileDumper("output1.cap");

    // register observer 
    auto observer1 = std::make_shared<PacketObserver>(*fileDumper1);
    dev->registerObserver(observer1);


    dev->loop();
    ASSERT_THAT (observer1->dumpCount, observer1->receivedCount/2); // TODO: need to have better checking (.e.g. check the content of output1.cap)

    
	
}


TEST(CppPcap, testASpecifiedPcapFile) {


    struct PacketObserver: public AbstractObserver<Packet> {
        void onNotified(const Packet& packet) override {
            receivedCount +=1;
        }

        int receivedCount=0;

    };

    if (g_argc==1) {    
        return;
    }
    std::string pcapFile=std::string(g_argv[1]);
    
    
    auto dev = openOffline(pcapFile);
    // register observer 
    auto observer = std::make_shared<PacketObserver>();
    dev->registerObserver(observer);

    
    dev->loop();
}    



int main(int argc, char *argv[])
{
	testing::InitGoogleMock (&argc, argv);
    g_argc = argc;
    g_argv=argv;

	return RUN_ALL_TESTS();
}

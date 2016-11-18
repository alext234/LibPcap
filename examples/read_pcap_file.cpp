#include "cpppcap.h"
#include <iostream>
using namespace Pcap;

int main(int argc, char*argv[]) {
    std::string pcapFile{SAMPLE_PCAP_DIR};
    pcapFile+="sample_http.cap";
    
    auto dev = openOffline(pcapFile);

    unsigned int packetCount=0;
    Packet::TimeStamp firstPacketTs;

    std::cout <<"No." << '\t'<<"Timestamp" <<std::endl;
    // register observer  with lambda 
    dev->registerObserver([&packetCount, &firstPacketTs](const Packet& packet){
        if (packetCount==0) {
            firstPacketTs = packet.ts();
        }
        ++packetCount;

        auto relTs = std::chrono::duration_cast<std::chrono::microseconds> (packet.ts() - firstPacketTs);
        std::cout << packetCount << '\t'<< relTs.count()/1000000 << '.'<< relTs.count()%1000000<<std::endl;


    });

    dev->loop();
    std::cout<<"Number of packets: "<< packetCount<< std::endl;


}

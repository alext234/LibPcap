#include "cpppcap.h"
#include <iostream>
#include <iomanip>
using namespace Pcap;

int main(int argc, char*argv[]) {
    std::string pcapFile{SAMPLE_PCAP_DIR};
    pcapFile+="sample_http.cap";
    
    auto dev = openOffline(pcapFile);

    uint32_t packetCount=0;
    Packet::TimeStamp firstPacketTs;
    enum {NO_WIDTH=6, LENGTH_WIDTH=10, TS_WIDTH=20, DATA_WIDTH=30};
    std::cout <<std::setw(NO_WIDTH)<<"No." << std::setw(LENGTH_WIDTH)<<"length"<<std::setw(TS_WIDTH)<<"Timestamp" <<std::endl;
    // register observer  with lambda 
    dev->registerObserver([&packetCount, &firstPacketTs](const Packet& packet){
        if (packetCount==0) {
            firstPacketTs = packet.ts();
        }
        ++packetCount;

        
        auto relTs = std::chrono::duration_cast<std::chrono::microseconds> (packet.ts() - firstPacketTs);
        auto relSeconds = relTs.count()/1000000;
        auto relmicroSecs = relTs.count()%1000000;
        std::ostringstream tsstream; 
        tsstream << relSeconds<<'.'<<relmicroSecs;

        std::cout <<std::setw(NO_WIDTH)<< packetCount <<std::setw(LENGTH_WIDTH)<< packet.len()<< std::setw(TS_WIDTH)<<tsstream.str() << std::setw(DATA_WIDTH)<<packet.dataHex(5) <<std::endl;


    });

    dev->loop();
    std::cout<<"Number of packets: "<< packetCount<< std::endl;


}

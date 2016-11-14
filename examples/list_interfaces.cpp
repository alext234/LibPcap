#include "cpppcap.h"
#include <iostream>

int main(int argc, char*argv[]) {
    std::cout << "list of interfaces :"<<std::endl;
    auto devList = Pcap::findAllDevs();
    for (auto it=devList.cbegin(); it!=devList.cend(); ++it) {
        std::cout<<*it<<std::endl;
    }
}

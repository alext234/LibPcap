#include "cpppcap.h"
#include <iostream>
#include "cpp_observer.h"
using namespace std;
using namespace Pcap;

// syntax:
// ./test_live eth0 
// or ./test_live  
// (use any default interface detected)
int main(int argc, char** argv) {
    
    shared_ptr<DevLive> dev;
    if (argc==2) {
        dev = openLive(argv[1]);
    } else {
        dev = lookUpDev();  
        if (dev==nullptr) {
            cout << "no interface found"<<endl;
            exit(1);
        }
    }
    
    cout<<*dev<< std::endl;  
    
    struct PacketObserver: public AbstractObserver<Packet> {
        PacketObserver(std::shared_ptr<DevLive> dev) : dev{dev} {}
        void onNotified(const Packet& packet) override {
            
            auto stat = dev -> getStats();
            cout << "\r";
            cout << "  received : "<< stat.recv;
            cout << "  dropped: "<< stat.drop;
            cout << "  ifdropped: "<< stat.ifdrop;
            cout <<flush;
        }


        std::shared_ptr<DevLive> dev;

    };
    auto observer = std::make_shared<PacketObserver>(dev);
    dev->registerObserver(observer);    
    dev->loop();
    

}

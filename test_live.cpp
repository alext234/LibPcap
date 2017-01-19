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
    
    shared_ptr<Dev> dev;
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
        PacketObserver(std::shared_ptr<Dev> dev) : dev{dev} {}
        void onNotified(const Packet& packet) override {
            receivedCount +=1;
            cout << "received : "<< receivedCount<< " packets" << endl;
        }

        int receivedCount=0;
        std::shared_ptr<Dev> dev;

    };
    auto observer = std::make_shared<PacketObserver>(dev);
    dev->registerObserver(observer);    
    dev->loop();
    

}

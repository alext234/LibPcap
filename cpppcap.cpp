#include "cpppcap.h"
#include "pcap.h"

namespace Pcap {

    std::vector<Dev> findAllDevs(void) throw (Error) {
        std::vector<Dev> devList;
        
        // C code
        char errbuf[PCAP_ERRBUF_SIZE+1];
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1){
            throw Error(std::string(errbuf));
        }
        // populate devList
        pcap_if_t *dev_it;
        for(dev_it=alldevs;dev_it;dev_it=dev_it->next){

            Dev dev{dev_it->name?std::string(dev_it->name):"", 
            dev_it->description?std::string(dev_it->description):""};
            dev._flags = dev_it->flags;

            devList.push_back (std::move(dev));
        }


        return devList;
    }

    std::ostream& operator<<(std::ostream& os, const Dev& dev) {
        os << "name: "<< dev._name 
        << "\n  " << "description: " << dev._description
        << "\n  " << "flags: "
        << (dev.isUp()?" UP " :" ")
        << (dev.isRunning()?" RUNNING " :" ")
        << (dev.isLoopback()?" LOOPBACK " :" ")
        
        ;
        return os;
    }
    
    Dev::Dev(Dev&& r) {
        _name = std::move(r._name);
        _description = std::move(r._description);
        _flags = r._flags;
    }
    
    
    bool Dev::isUp() const{ 
        return _flags & PCAP_IF_UP;
    }

    bool Dev::isRunning() const{
        return _flags & PCAP_IF_RUNNING;
    }

    bool Dev::isLoopback() const{
        return _flags & PCAP_IF_LOOPBACK;
    }
} // namespace Pcap 

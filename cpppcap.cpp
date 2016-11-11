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
            devList.emplace_back (  std::string{dev_it->name},
                                    (dev_it->description)?std::string{dev_it->description}:""
                                 );
        }


    
        ////

        return devList;
    }

    std::ostream& operator<<(std::ostream& os, const Dev& dev) {
        os << "name: "<< dev._name << "   " << "description: " << dev._description;
        return os;
    }
} // namespace Pcap 

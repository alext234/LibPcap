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
        // TODO: populate devList

    
        ////

        return devList;
    }

} // namespace Pcap 

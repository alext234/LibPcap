#include "cpppcap.h"
#include "pcap.h"

namespace Pcap {
    class Wrapper_pcap_if_t {
    public:
        Wrapper_pcap_if_t(pcap_if_t* if_ptr): pcap_if_ptr{if_ptr} {}
        pcap_if_t* pcap_if_ptr;
    };

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
            Wrapper_pcap_if_t pcap_if{dev_it};
            devList.push_back (Dev{pcap_if});
        }


    
        ////

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

    
    Dev::Dev(Wrapper_pcap_if_t pcap_if) :
    _name{pcap_if.pcap_if_ptr->name},
    _description{(pcap_if.pcap_if_ptr->description)?pcap_if.pcap_if_ptr->description:"" },
    _flags{pcap_if.pcap_if_ptr->flags}
    {      }

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

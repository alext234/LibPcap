#include "cpppcap.h"
#include "pcap.h"
#include <sstream>
#include <iterator>
#include <algorithm>
#include <iomanip>

namespace Pcap {

    std::vector< std::shared_ptr<Dev> > findAllDevs(void) throw (Error) {
        std::vector< std::shared_ptr<Dev> > devList;
        
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

            devList.push_back (std::make_shared<Dev> (std::move(dev)));
        }

        pcap_freealldevs(alldevs);

        return devList;
    }

    std::shared_ptr<Dev> lookUpDev(void) throw(Error) {
        // based on reference implementation from original libpcap
        auto devList = findAllDevs();
        if (devList.size()==0) {
            return nullptr;
        }
        auto first = *(devList.cbegin());
        if (first->isLoopback()) {
            return nullptr;
        }

        return  first;

        
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
    
    Dev::Dev(const std::string& name, const std::string& description):_name{name},_description{description},
            _cwrapper{std::make_unique<CPcapWrapper>()}
    {
        _flags =0;
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
  
    Dev::~Dev() {  
    }


    class Dev::CPcapWrapper {
    public:
        CPcapWrapper() {
            _handler = nullptr;
        } 
        ~CPcapWrapper () {
            if (_handler!=nullptr) {
                pcap_close(_handler);
                _handler=nullptr;
            }
        }
    
        // call back function to be used with pcap_loop or pcap_dispatch
        static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) { 
            Dev *dev = reinterpret_cast<Dev*>(param);
            Packet packet;
            packet._len = header->len;
            packet._ts = Packet::TimeStamp(std::chrono::microseconds(header->ts.tv_sec*1000000+header->ts.tv_usec));
            packet._data.reserve(header->len);
            packet._data.assign(pkt_data, pkt_data+header->len);  // copy from array

            dev -> notifyObservers(packet);
           
        }
        pcap_t *_handler;    // used to store returned  handled from pcap_open_* functions        
      
    };



    void Dev::loop(void) {
        if (!_cwrapper->_handler) {
            return;
        }
        
        pcap_loop(_cwrapper->_handler, 0, &Dev::CPcapWrapper::packet_handler, reinterpret_cast<u_char*>(this));

    }

    std::shared_ptr<Dev>  openOffline(const std::string& savefile, tstamp_precision precision) throw(Error){

        char errbuf[PCAP_ERRBUF_SIZE+1];
        pcap_t *handler = pcap_open_offline_with_tstamp_precision(savefile.c_str(), precision, errbuf);
        if (handler==nullptr) {
            throw Error(std::string(errbuf));
        }
        auto dev = std::make_shared<Dev>(savefile);
        dev->_cwrapper->_handler = handler;

        return dev;

    
       
    }



    std::string Packet::dataHex (uint16_t n, std::string separator) const {
        std::ostringstream ss;
        if (n>_data.size()) n=_data.size();
        ss<<std::setfill('0')<<std::hex;
        for (auto it= _data.cbegin(); it!=_data.cbegin()+n; ++it) {
            ss<<std::setw(2)<<static_cast<unsigned>(*it)<<separator;
        }
        return ss.str();
    }

} // namespace Pcap 

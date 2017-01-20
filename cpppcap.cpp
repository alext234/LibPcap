#include "cpppcap.h"
#include "pcap.h"
#include <sstream>
#include <iterator>
#include <algorithm>
#include <iomanip>
#include <assert.h>

namespace Pcap {
    using namespace std;

    vector< shared_ptr<DevLive> > findAllDevs(void) throw (Error) {
        vector< shared_ptr<DevLive> > devList;
        
        // C code
        char errbuf[PCAP_ERRBUF_SIZE+1];
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1){
            throw Error(string(errbuf));
        }
        // populate devList
        pcap_if_t *dev_it;
        for(dev_it=alldevs;dev_it;dev_it=dev_it->next){

            DevLive dev{dev_it->name?string(dev_it->name):"", 
            dev_it->description?string(dev_it->description):""};
            dev._flags = dev_it->flags;

            devList.push_back (make_shared<DevLive> (move(dev)));
        }

        pcap_freealldevs(alldevs);

        return devList;
    }

    shared_ptr<DevLive> lookUpDev(void) throw(Error) {
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

    ostream& operator<<(ostream& os, const Dev& dev) {
        os << "name: "<< dev._name 
        << "\n  " << "description: " << dev._description
        << "\n  " ;
        ;
        return os;
    }
    ostream& operator<<(ostream& os, const DevLive& dev) {
        return operator<<(os,dynamic_cast<const Dev&> (dev)) << "flags: "
        << (dev.isUp()?" UP " :" ")
        << (dev.isRunning()?" RUNNING " :" ")
        << (dev.isLoopback()?" LOOPBACK " :" ");
        
    }
    
        

    bool operator==(const Packet& packet1, const Packet& packet2) {
        if (packet1._len!=packet2._len) return false;
        if (packet1._caplen!=packet2._caplen) return false;
        if (packet1._ts != packet2._ts) return false;
        auto it1=packet1._data.cbegin();
        auto it2=packet2._data.cbegin();
        for (;it1!=packet1._data.cend();) {
            if (*it1!=*it2) return false;
            ++it1; ++it2;
        }
        return true;
    }
    
    Dev::Dev(const string& name, const string& description):_name{name},_description{description},
            _cwrapper{make_unique<CPcapWrapper>()}
    {
        
    }

    Dev::Dev(Dev&& r) {
        _name = move(r._name);
        _description = move(r._description);        
        _cwrapper = move(r._cwrapper);
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
            packet._caplen = header->caplen;
            packet._ts = Packet::TimeStamp(chrono::microseconds(header->ts.tv_sec*1000000+header->ts.tv_usec));
            packet._data.reserve(header->len);
            packet._data.assign(pkt_data, pkt_data+header->caplen);  // copy from array

            dev -> notifyObservers(packet);
           
        }
        pcap_t *_handler;    // used to store returned  handled from pcap_open_* functions        
      
    };

    void Dev::breakLoop(void) {
        assert (_cwrapper!=nullptr);
        if (_cwrapper->_handler==nullptr) {
            return;
        }
        pcap_breakloop(_cwrapper->_handler);
        
    }


    void Dev::loop(void) {
        assert (_cwrapper!=nullptr);
        
        pcap_loop(_cwrapper->_handler, 0, &Dev::CPcapWrapper::packet_handler, reinterpret_cast<u_char*>(this));

    }
    auto Dev::getStats () -> Stats {
        return {0,0,0};
    }
  
    bool DevLive::isUp() const{ 
        return _flags & PCAP_IF_UP;
    }

    bool DevLive::isRunning() const{
        return _flags & PCAP_IF_RUNNING;
    }

    bool DevLive::isLoopback() const{
        return _flags & PCAP_IF_LOOPBACK;
    }
  
    auto  DevLive::getStats () -> Stats{
        struct pcap_stat _stat;
        int err  = pcap_stats(_cwrapper->_handler,  &_stat);
        if (err==-1) {
            throw Error(pcap_geterr(_cwrapper->_handler));
        }
        
        return {_stat.ps_recv,_stat.ps_drop,_stat.ps_ifdrop};
    }
    
    DevOffline::DevOffline(const std::string& name, const std::string& description) : Dev(name,description) {
        registerObserver([this](const Packet& packet){
            stats.recv+=1;
        });

    }
    
    
    auto DevOffline::getStats () -> Stats {
        return stats;
    }
    
    struct PacketObserver: public AbstractObserver<Packet> {
        PacketObserver(Dumper&d):_dumper(d) {}
        void onNotified(const Packet& packet) override {
            _dumper.dumpPacket (packet);
    
        }
        Dumper& _dumper;
    };
    void Dev::loop(const vector<shared_ptr<Dumper>>& dumperList) {

        
        vector<shared_ptr<PacketObserver>> dumpObservers;
        for (auto it: dumperList) {
            
            auto observer = make_shared<PacketObserver> ( (*it) );
            dumpObservers.push_back(observer);
            this->registerObserver ( observer);
        }


        loop();

        for (auto it:dumpObservers ) {
            
            this->registerObserver ( it);
        }
    }
    void Dev::loop(Dumper& dumper) {
        auto dumpObserver = make_shared <PacketObserver> (dumper);

        this->registerObserver (dumpObserver);

        loop();

        this->deregisterObserver (dumpObserver);

        

    }

    shared_ptr<DevOffline>  openOffline(const string& savefile, tstamp_precision precision) throw(Error){

        char errbuf[PCAP_ERRBUF_SIZE+1];
        pcap_t *handler = pcap_open_offline_with_tstamp_precision(savefile.c_str(), precision, errbuf);
        if (handler==nullptr) {
            throw Error(string(errbuf));
        }
        auto dev = make_shared<DevOffline>(savefile);
        dev->_cwrapper->_handler = handler;

        return dev;

    
       
    }


    std::shared_ptr<DevLive> openLive(string name) throw(Error) {
        auto devList = findAllDevs();
        if (devList.size()==0) {
            throw Error ("system has 0 interfaces");
        }
        auto it= find_if (devList.cbegin(), devList.cend(), [&name] (const shared_ptr<DevLive>& d) -> bool {
            return d->name() == name;
        });
        if (it==devList.cend()) {
            throw Error ("interface "+name + " not found");
        }
        return *it;
    }
    
    void DevLive::loop(void) {
        if (_cwrapper->_handler==nullptr) {
            // most likely live interface, let's use open_live
            char errbuf[PCAP_ERRBUF_SIZE+1];
            _cwrapper->_handler =    pcap_open_live(_name.c_str(), BUFSIZ, 1, 1000, errbuf); 
            if (_cwrapper->_handler==nullptr)  {
                throw Error(string(errbuf));
            }
            
        }
        
        Dev::loop();
    }

    string Packet::dataHex (uint16_t n, string separator) const {
        ostringstream ss;
        if (n>_data.size()) n=_data.size();
        ss<<setfill('0')<<hex;
        for (auto it= _data.cbegin(); it!=_data.cbegin()+n; ++it) {
            ss<<setw(2)<<static_cast<unsigned>(*it)<<separator;
        }
        return ss.str();
    }

    shared_ptr<FileDumper> Dev::generateFileDumper(string filename){

        shared_ptr<FileDumper> fd(new FileDumper (*this,filename));
        
        return fd; 
    
    }

    class FileDumper::CPcapWrapper {
    public: 
        CPcapWrapper() {
            _handler = nullptr;
        } 
        ~CPcapWrapper () {
            if (_handler!=nullptr) {
                pcap_dump_close(_handler);
                _handler=nullptr;
            }
        }
        pcap_dumper_t* _handler;

        
    };

    FileDumper::FileDumper (const Dev& dev,string filename) throw (Error):  
            _packetCount(0), _cwrapper{make_unique<CPcapWrapper>()} {

        pcap_t *pcap_handler = dev._cwrapper->_handler;
        if (pcap_handler==nullptr) throw Error ("pcap_handler is null ");
        pcap_dumper_t *dump_handler = pcap_dump_open(pcap_handler, filename.c_str());
        if (dump_handler==nullptr) {
            throw Error(string(pcap_geterr(pcap_handler)));
        }
        _cwrapper->_handler = dump_handler;
    }

    void FileDumper::dumpPacket(const Packet& packet) {
        struct pcap_pkthdr hdr;

        if (!_cwrapper->_handler) return;
        auto ts_micro = chrono::duration_cast<chrono::microseconds>(packet.ts().time_since_epoch()).count();
        hdr.ts.tv_sec =  ts_micro/1000000;
        hdr.ts.tv_usec =  ts_micro%1000000;
        hdr.len = packet._len;
        hdr.caplen  = packet._caplen;
        pcap_dump ((u_char*)(_cwrapper->_handler), &hdr, &packet.data()[0]);
        ++_packetCount;

    }
    FileDumper::~FileDumper() {    }

} // namespace Pcap 

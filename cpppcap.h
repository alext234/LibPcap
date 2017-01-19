#ifndef __LIB_CPPPCAP__
#define __LIB_CPPPCAP__

#include <vector>
#include <string>
#include <stdexcept>
#include <ostream>
#include <memory> 
#include <chrono>
#include <cstdint>
#include "cpp_observer.h"

namespace Pcap {

    class Error : public std::runtime_error {       
    public:
        Error (const std::string& what_arg): std::runtime_error{what_arg} {}
    };
    
    enum tstamp_precision{
        TSTAMP_PRECISION_MICRO=0,
        TSTAMP_PRECISION_NANO
    };

    class Dumper;
    class Packet {
    public:
        using TimeStamp =   std::chrono::time_point<std::chrono::high_resolution_clock> ;
        const TimeStamp& ts() const { return const_cast<const TimeStamp&>(_ts);}
        uint16_t len()const {return (_caplen<_len?_caplen:_len);}
        const std::vector<uint8_t>& data() const{ return _data;}
        
        std::string dataHex (uint16_t n, std::string separator=" ") const;   
    private:        
        uint16_t _len;
        uint16_t _caplen;
        TimeStamp _ts;
        std::vector<uint8_t> _data;
        friend  class Dev;
        friend class FileDumper;
        
        friend bool operator==(const Packet&, const Packet&);
    };
    bool operator==(const Packet&, const Packet&);

    class Dev;
    class DevOffline;
    class DevLive;
    
    class Dumper {
    public:
        virtual ~Dumper() {}
        virtual void dumpPacket (const Packet&)=0;
    };
    class FileDumper: public Dumper {
    public:
        ~FileDumper();
        FileDumper(const Dev& dev, std::string filename) throw (Error);
        FileDumper(const FileDumper&)=delete;
        FileDumper& operator=(const FileDumper&)=delete;

        void dumpPacket (const Packet&) override ;
        uint32_t packetCount() {return _packetCount;} // return number of packets being dumped
    private:     
        class CPcapWrapper;
        uint32_t _packetCount;
        std::unique_ptr<CPcapWrapper> _cwrapper;         
        
    };

    class Dev: public Observable<Packet> {
    public:       
        Dev(const std::string& name, const std::string& description="");
        virtual ~Dev() ;

        std::string name() const { return _name;}
        std::string description() const { return _description;}
        
        Dev() = delete;
        Dev(const Dev&)=delete;
        Dev(Dev&& r);

        void breakLoop(void); 
        virtual void loop(void); // start the receive loop
        void loop(Dumper&);
        void loop(const std::vector<std::shared_ptr<Dumper>>&);
        std::shared_ptr<FileDumper> generateFileDumper(std::string filename); // get a fileDumper which can be used to write packet 
        
    protected:
        std::string _name;
        std::string _description;
        
        
        class CPcapWrapper;
        std::unique_ptr<CPcapWrapper> _cwrapper; //  to store all stuff from orginal libpcap such as pcap_t handler 
    
        void notify (const Packet& packet);
        // 'friends'
        friend std::ostream& operator<<(std::ostream& os, const Dev& dev);        
        friend class CPcapWrapper;
        friend class FileDumper;
        friend std::vector< std::shared_ptr<DevLive> > findAllDevs(void) throw(Error);        
        friend std::shared_ptr<DevOffline>  openOffline(const std::string& savefile, tstamp_precision precision) throw(Error);
    };
   
    // offline .pcap file
    class DevOffline: public Dev {
    public:        
        using Dev::Dev;
    
        
    };
    
    // a live interface
    class DevLive: public Dev {
    public:
        using Dev::Dev;                
        virtual void loop(void) override;
        bool isUp() const;
        bool isRunning() const;
        bool isLoopback()const ;
        friend std::vector< std::shared_ptr<DevLive> > findAllDevs(void) throw(Error);        

    private:
        uint32_t _flags=0;
        friend std::ostream& operator<<(std::ostream& os, const DevLive& dev);        
    };
    
    // most of the api below follow the same naming convention as the original libpcap http://www.tcpdump.org/manpages/
    std::vector< std::shared_ptr<DevLive> > findAllDevs(void) throw(Error);
    std::shared_ptr<DevLive> lookUpDev(void) throw(Error);
    std::shared_ptr<DevOffline>  openOffline(const std::string& savefile, tstamp_precision precision=TSTAMP_PRECISION_MICRO) throw(Error);

}

// TODO: too much friendship; cleanup needed
#endif //__LIB_CPPPCAP__

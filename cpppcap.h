#ifndef __LIB_CPPPCAP__
#define __LIB_CPPPCAP__

#include <vector>
#include <string>
#include <stdexcept>
#include <ostream>
#include <memory> 
#include <chrono>
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

    class Packet {
    public:
        using TimeStamp =   std::chrono::time_point<std::chrono::high_resolution_clock> ;
        //Packet (const Packet& lhs); // TODO: implement deep copy
        //Packet& operator=(const Packet& lhs); // TODO: implement deep copy

        const TimeStamp& ts() const { return const_cast<const TimeStamp&>(_ts);}
    private:        
        unsigned int _len;
        TimeStamp _ts;
        const unsigned char* _data;
        friend  class Dev;
        
    };

    class Dev: public Observable<Packet> {
    public:
        Dev(const std::string& name, const std::string& description="");
        ~Dev() ;

        std::string name() const { return _name;}
        std::string description() const { return _description;}
        bool isUp() const;
        bool isRunning() const;
        bool isLoopback()const ;
        Dev(const Dev&)=default;
        Dev(Dev&& r);


        void loop(void); // start the receive loop
    private:
        std::string _name;
        std::string _description;
        uint32_t _flags;        

        class CPcapWrapper;
        std::unique_ptr<CPcapWrapper> _cwrapper; //  to store all stuff from orginal libpcap such as pcap_t handler 

        void notify (const Packet& packet);
        // 'friends'
        friend std::ostream& operator<<(std::ostream& os, const Dev& dev);
        friend std::vector< std::shared_ptr<Dev> > findAllDevs(void) throw(Error);
        friend std::shared_ptr<Dev>  openOffline(const std::string& savefile, tstamp_precision precision) throw(Error);
        friend class CPcapWrapper;
    };
   
    // most of the api below follow the same naming convention as the original libpcap http://www.tcpdump.org/manpages/
    std::vector< std::shared_ptr<Dev> > findAllDevs(void) throw(Error);
    std::shared_ptr<Dev> lookUpDev(void) throw(Error);
    std::shared_ptr<Dev>  openOffline(const std::string& savefile, tstamp_precision precision=TSTAMP_PRECISION_MICRO) throw(Error);

}
#endif //__LIB_CPPPCAP__

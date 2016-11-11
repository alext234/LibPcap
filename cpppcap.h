#ifndef __LIB_CPPPCAP__
#define __LIB_CPPPCAP__

#include <vector>
#include <string>
#include <stdexcept>
#include <ostream>

namespace Pcap {

    class Error : public std::runtime_error {       
    public:
        Error (const std::string& what_arg): std::runtime_error{what_arg} {}
    };
    
    class Wrapper_pcap_if_t;
    class Dev {
    public:
        Dev(const std::string& name, const std::string& description=""):_name{name},_description{description},_flags{0} {}
        Dev(Wrapper_pcap_if_t dev);  // this constructor is typically used by findAllDevs

        std::string name() const { return _name;}
        std::string description() const { return _description;}
        bool isUp() const;
        bool isRunning() const;
        bool isLoopback()const ;
    private:
        std::string _name;
        std::string _description;
        uint32_t _flags;        

        friend std::ostream& operator<<(std::ostream& os, const Dev& dev);
    };
    
    
    std::vector<Dev> findAllDevs(void) throw(Error);

}
#endif //__LIB_CPPPCAP__

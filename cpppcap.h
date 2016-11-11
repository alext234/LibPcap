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
    
    class Dev {
    public:
        Dev(const std::string& name, const std::string& description):_name{name},_description{description} {}
        std::string name(){ return _name;}
        std::string description(){ return _description;}
    private:
        std::string _name;
        std::string _description;

        friend std::ostream& operator<<(std::ostream& os, const Dev& dev);
    };
    
    
    std::vector<Dev> findAllDevs(void) throw(Error);

}
#endif //__LIB_CPPPCAP__

#ifndef __LIB_CPPPCAP__
#define __LIB_CPPPCAP__

#include <vector>
#include <string>
#include <stdexcept>


namespace Pcap {

    class Error : public std::runtime_error {       
    public:
        Error (const std::string& what_arg): std::runtime_error{what_arg} {}
    };
    
    class Dev {
    };
    
    
    std::vector<Dev> findAllDevs(void) throw(Error);

}
#endif //__LIB_CPPPCAP__

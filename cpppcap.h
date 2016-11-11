#ifndef __LIB_CPPPCAP__
#define __LIB_CPPPCAP__

#include <vector>
#include <string>
#include <stdexcept>
#include <ostream>
#include <iostream>

namespace Pcap {

    class Error : public std::runtime_error {       
    public:
        Error (const std::string& what_arg): std::runtime_error{what_arg} {}
    };
    
    class Dev {
    public:
        Dev(const std::string& name, const std::string& description=""):_name{name},_description{description},_flags{0} {}

        std::string name() const { return _name;}
        std::string description() const { return _description;}
        bool isUp() const;
        bool isRunning() const;
        bool isLoopback()const ;
        Dev(const Dev&)=default;
        Dev(Dev&& r);
    private:
        std::string _name;
        std::string _description;
        uint32_t _flags;        

        friend std::ostream& operator<<(std::ostream& os, const Dev& dev);
        friend std::vector<Dev> findAllDevs(void) throw(Error);
    };
    
    
    std::vector<Dev> findAllDevs(void) throw(Error);

}
#endif //__LIB_CPPPCAP__

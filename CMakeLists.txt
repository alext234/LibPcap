cmake_minimum_required(VERSION 2.8)

project(LibPcap)

add_subdirectory(googletest)


set(LIBPCAP ${CMAKE_SOURCE_DIR}/libpcap)  
set(LIBPCAP_STATIC ${CMAKE_SOURCE_DIR}/libpcap/libpcap.a)  
add_custom_command(
    OUTPUT  ${LIBPCAP_STATIC}
    COMMAND cwd=$(pwd) && cd ${LIBPCAP} && pwd && ./configure --enable-dbus=no --enable-bluetooth=no --enable-usb=no && make && cd ${cwd}
)


add_library (cpppcap STATIC cpppcap.h cpppcap.cpp ${LIBPCAP_STATIC})

set(GOOGLETEST ${CMAKE_SOURCE_DIR}/googletest/)  
include_directories(${LIBPCAP})
include_directories(${GOOGLETEST}/googlemock/include ${GOOGLETEST}/googletest/include)
link_directories(${GOOGLETEST}/build/googlemock ${GOOGLETEST}/build/googlemock/gtest)

# set build type: cmake -DCMAKE_BUILD_TYPE=Debug  ; to see all options of AddressSanitizer, set the environment variable ASAN_OPTIONS=help=1
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -std=c++1y -Wall -Wextra -Wno-unused-parameter -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -g -std=c++1y -Wall -Wextra -Wno-unused-parameter")


add_executable(runtests  tests.cpp)
set(SAMPLE_PCAP_DIR ${CMAKE_SOURCE_DIR}/examples/)
set_target_properties(runtests PROPERTIES COMPILE_FLAGS -D'SAMPLE_PCAP_DIR="${SAMPLE_PCAP_DIR}"')
target_link_libraries(runtests gmock)
target_link_libraries(runtests gtest)
target_link_libraries(runtests pthread)
target_link_libraries(runtests cpppcap)
target_link_libraries(runtests ${LIBPCAP_STATIC})

add_subdirectory(examples)

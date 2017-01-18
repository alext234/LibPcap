cmake_minimum_required(VERSION 2.8)

project(LibPcap)

add_subdirectory(googletest)


set(LIBPCAP ${CMAKE_CURRENT_SOURCE_DIR}/libpcap)  
set(LIBPCAP_STATIC ${CMAKE_CURRENT_SOURCE_DIR}/libpcap/libpcap.a)  

set(CPPOBSERVER ${CMAKE_CURRENT_SOURCE_DIR}/cppobserver)  
add_custom_command(
    OUTPUT  ${LIBPCAP_STATIC}
    COMMAND cwd=$(pwd) && cd ${LIBPCAP} && pwd && ./configure --enable-dbus=no --enable-bluetooth=no --enable-usb=no && make && cd ${cwd}
)

add_library (cpppcap STATIC cpppcap.h cpppcap.cpp ${LIBPCAP_STATIC})
add_library (pcap STATIC IMPORTED GLOBAL)
set_target_properties(pcap PROPERTIES IMPORTED_LOCATION ${LIBPCAP_STATIC})
link_directories(${LIBPCAP})

set(GOOGLETEST ${CMAKE_CURRENT_SOURCE_DIR}/googletest/)  
include_directories(${LIBPCAP})
include_directories(${GOOGLETEST}/googlemock/include ${GOOGLETEST}/googletest/include)
link_directories(${GOOGLETEST}/build/googlemock ${GOOGLETEST}/build/googlemock/gtest)
include_directories(${CPPOBSERVER})

# set build type: cmake -DCMAKE_BUILD_TYPE=Debug  ; to see all options of AddressSanitizer, set the environment variable ASAN_OPTIONS=help=1
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -std=c++1y -Wall -Wextra -Wno-unused-parameter -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -g -std=c++1y -Wall -Wextra -Wno-unused-parameter")


add_executable(runtests_cpppcap  tests.cpp)
set(SAMPLE_PCAP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/examples/)
set_target_properties(runtests_cpppcap PROPERTIES COMPILE_FLAGS -D'SAMPLE_PCAP_DIR="${SAMPLE_PCAP_DIR}"')
target_link_libraries(runtests_cpppcap gmock)
target_link_libraries(runtests_cpppcap gtest)
target_link_libraries(runtests_cpppcap pthread)
target_link_libraries(runtests_cpppcap cpppcap)
target_link_libraries(runtests_cpppcap pcap)

add_subdirectory(examples)


add_executable(test_live test_live.cpp)
target_link_libraries(test_live cpppcap)
target_link_libraries(test_live pcap)

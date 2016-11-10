cmake_minimum_required(VERSION 2.8)

project(LibPcap)

add_subdirectory(googletest)


set(LIBPCAP ${CMAKE_SOURCE_DIR}/libpcap)  
set(LIBPCAP_STATIC ${CMAKE_SOURCE_DIR}/libpcap/libpcap.a)  
add_custom_command(
    OUTPUT  ${LIBPCAP_STATIC}
    COMMAND cwd=$(pwd) && cd ${LIBPCAP} && pwd && ./configure && make && cd ${cwd}
)


add_library (cpppcap cpppcap.h cpppcap.cpp ${LIBPCAP_STATIC})

set(GOOGLETEST ${CMAKE_SOURCE_DIR}/googletest/)  
include_directories(${GOOGLETEST}/googlemock/include ${GOOGLETEST}/googletest/include)
link_directories(${GOOGLETEST}/build/googlemock ${GOOGLETEST}/build/googlemock/gtest)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++1y -Wall -Wextra -Wno-unused-parameter")


add_executable(runtests  tests.cpp)
target_link_libraries(runtests gmock)
target_link_libraries(runtests gtest)
target_link_libraries(runtests pthread)
target_link_libraries(runtests cpppcap)

add_subdirectory(examples)

project(LibPcap_example)

include_directories(${CMAKE_SOURCE_DIR})

add_executable(list_interfaces  list_interfaces.cpp)
target_link_libraries(list_interfaces cpppcap ${LIBPCAP_STATIC})

add_executable(read_pcap_file  read_pcap_file.cpp)
set_target_properties(read_pcap_file PROPERTIES COMPILE_FLAGS -D'SAMPLE_PCAP_DIR="${SAMPLE_PCAP_DIR}"')
target_link_libraries(read_pcap_file cpppcap ${LIBPCAP_STATIC})

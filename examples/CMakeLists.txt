project(LibPcap_example)

include_directories(${CMAKE_SOURCE_DIR})

add_executable(list_interfaces  list_interfaces.cpp)
target_link_libraries(list_interfaces cpppcap ${LIBPCAP_STATIC})

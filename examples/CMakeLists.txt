project(LibPcap_example)

include_directories(${CMAKE_SOURCE_DIR})

add_executable(simple_example  simple_example.cpp)
target_link_libraries(simple_example cpppcap)

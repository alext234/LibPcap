cmake_minimum_required(VERSION 2.8)

project(cppobserver)

add_subdirectory(googletest)

set(GOOGLETEST ${CMAKE_SOURCE_DIR}/googletest/)  
include_directories(${GOOGLETEST}/googlemock/include ${GOOGLETEST}/googletest/include)
link_directories(${GOOGLETEST}/build/googlemock ${GOOGLETEST}/build/googlemock/gtest)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++1y -Wall -Wextra -Wno-unused-parameter")


add_executable(runtests  tests.cpp)
target_link_libraries(runtests gmock)
target_link_libraries(runtests gtest)
target_link_libraries(runtests pthread)

add_subdirectory(examples)

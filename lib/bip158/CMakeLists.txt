CMAKE_MINIMUM_REQUIRED(VERSION 3.1.0 FATAL_ERROR)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE "RELEASE")
ENDIF()

project(chiabip158)

include_directories(
  ${INCLUDE_DIRECTORIES}
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  /usr/local/opt/openssl/include
  )

set (CMAKE_CXX_FLAGS "-DHAVE_WORKING_BOOST_SLEEP -g -O3 -Wall -msse2 -msse -march=native -std=c++14 -maes")

FILE(GLOB_RECURSE MyCSources src/*.cpp)
ADD_LIBRARY(biplib ${MyCSources}) 

add_subdirectory(lib/pybind11)

pybind11_add_module(chiabip158 
  ${CMAKE_CURRENT_SOURCE_DIR}/python-bindings/chiabip158.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/python-bindings/PyBIP158.cpp)

add_executable(bip158
    main.cpp
)

target_link_libraries(bip158 biplib -lboost_system -lpthread -lboost_thread -lboost_filesystem -lssl -lcrypto)
target_link_libraries(chiabip158 PRIVATE biplib -lboost_system -lpthread -lboost_thread -lboost_filesystem -lssl -lcrypto)


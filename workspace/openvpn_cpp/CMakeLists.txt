cmake_minimum_required(VERSION 3.10)
project(OpenVPN_CPP)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(openvpn_cpp main.cpp)

target_link_libraries(openvpn_cpp OpenSSL::SSL OpenSSL::Crypto)

target_compile_options(openvpn_cpp PRIVATE -Wall -Wextra)

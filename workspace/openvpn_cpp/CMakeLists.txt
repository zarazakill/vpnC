cmake_minimum_required(VERSION 3.10)
project(OpenVPN_CPP)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

# Collect all source files
file(GLOB SOURCES "src/*.cpp")

# Create the executable
add_executable(openvpn_cpp ${SOURCES})

# Include directories
target_include_directories(openvpn_cpp PRIVATE include)

# Link libraries
target_link_libraries(openvpn_cpp OpenSSL::SSL OpenSSL::Crypto)

target_compile_options(openvpn_cpp PRIVATE -Wall -Wextra)

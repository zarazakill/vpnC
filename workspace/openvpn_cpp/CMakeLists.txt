cmake_minimum_required(VERSION 3.10)
project(OpenVPNClient VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Настройка компилятора
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -pedantic")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endif()

# Поиск библиотек
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Включаемые директории
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# Список исходных файлов
set(SOURCES
    src/config/OpenVPNConfig.cpp
    src/config/ConfigParser.cpp
    src/network/UDPClient.cpp
    src/network/SSLWrapper.cpp
    src/network/PacketProcessor.cpp
    src/crypto/EncryptionManager.cpp
    src/crypto/KeyExchange.cpp
    src/crypto/HMACGenerator.cpp
    src/interface/TUNInterface.cpp
    src/interface/NetworkManager.cpp
    src/auth/AuthenticationManager.cpp
    src/auth/CertificateManager.cpp
    src/session/OpenVPNSession.cpp
    src/session/SessionManager.cpp
    src/utils/Logger.cpp
    src/utils/ThreadPool.cpp
    src/utils/Statistics.cpp
    src/core/OpenVPNClient.cpp
    src/core/ConnectionManager.cpp
    src/core/StateMachine.cpp
    main.cpp
)

# Создание исполняемого файла
add_executable(${PROJECT_NAME} ${SOURCES})

# Подключение библиотек
target_link_libraries(${PROJECT_NAME}
    PRIVATE
    ${OPENSSL_LIBRARIES}
    Threads::Threads
    rt
    dl
)

# Установка
install(TARGETS ${PROJECT_NAME} DESTINATION bin)

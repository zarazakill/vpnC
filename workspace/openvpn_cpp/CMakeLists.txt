cmake_minimum_required(VERSION 3.14)
project(OpenVPNClient 
    VERSION 1.0.0 
    DESCRIPTION "OpenVPN Client Implementation in C++"
    LANGUAGES CXX
)

# Настройки проекта
set(PROJECT_NAME ${PROJECT_NAME})
set(PROJECT_VERSION ${PROJECT_VERSION})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Стандарт C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Опции сборки
option(BUILD_TESTS "Build tests" OFF)
option(BUILD_EXAMPLES "Build examples" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(ENABLE_ASAN "Enable Address Sanitizer" OFF)
option(ENABLE_UBSAN "Enable Undefined Behavior Sanitizer" OFF)
option(ENABLE_LTO "Enable Link Time Optimization" OFF)

# Флаги компилятора
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    # Предупреждения
    set(WARNING_FLAGS
        -Wall
        -Wextra
        -Werror
        -Wpedantic
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
    )
    
    # Оптимизация для Release
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        list(APPEND WARNING_FLAGS -O3 -DNDEBUG)
        if(ENABLE_LTO)
            list(APPEND WARNING_FLAGS -flto)
        endif()
    endif()
    
    # Отладка для Debug
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        list(APPEND WARNING_FLAGS -g3 -O0 -DDEBUG)
        if(ENABLE_ASAN)
            list(APPEND WARNING_FLAGS -fsanitize=address -fno-omit-frame-pointer)
        endif()
        if(ENABLE_UBSAN)
            list(APPEND WARNING_FLAGS -fsanitize=undefined)
        endif()
    endif()
    
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WARNING_FLAGS}")
    
elseif(MSVC)
    # Флаги для MSVC
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX")
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /DNDEBUG")
    endif()
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zi /Od /DEBUG")
    endif()
endif()

# Поиск зависимостей
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Threads REQUIRED)

# Включаемые директории
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# Поддиректории
add_subdirectory(src)

# Исполняемый файл
add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME}
    PRIVATE
    OpenVPNClientCore
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

# Установка
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)

# Тесты
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Примеры
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

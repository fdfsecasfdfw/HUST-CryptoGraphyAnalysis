cmake_minimum_required(VERSION 4.0)
project(CryptographyAnalysis)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-pedantic-errors)

if(MSVC)
    add_compile_options(/arch:AVX2)
else()
    add_compile_options(-march=native)
endif()

# 可执行文件输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# 静态库输出目录
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# 动态库输出目录
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# 区分不同配置（Debug/Release）
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/lib/Debug")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/lib/Release")

set(sourceDir "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(utilsDir "${sourceDir}/utils")
set(attackDir "${sourceDir}/Attack")

file(GLOB_RECURSE utilsSrc "${utilsDir}/*.cpp")
file(GLOB_RECURSE attackSrc "${attackDir}/*.cpp")

add_library(utils STATIC ${utilsSrc})
target_include_directories(utils PUBLIC "include/utils")

add_library(attack STATIC ${attackSrc})
target_include_directories(attack PUBLIC "include/Attack" "include/utils" "include/BlockCipher" "include/Z3")

add_executable(app
    src/main.cpp
)

target_include_directories(app PRIVATE "include/BlockCipher" "include/Attack")
target_link_libraries(app PRIVATE z3 utils attack)
target_link_directories(app PRIVATE "libs")
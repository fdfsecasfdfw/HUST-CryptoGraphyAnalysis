cmake_minimum_required(VERSION 3.20)
project(CryptographyAnalysis)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(OUTPUT_BIN_DIR "${CMAKE_BINARY_DIR}/bin")
set(OUTPUT_LIB_DIR "${CMAKE_BINARY_DIR}/lib")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${OUTPUT_BIN_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${OUTPUT_BIN_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${OUTPUT_LIB_DIR}")

foreach(CONFIG ${CMAKE_CONFIGURATION_TYPES})
 string(TOUPPER ${CONFIG} CONFIG)
 set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG} "${OUTPUT_BIN_DIR}")
 set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG} "${OUTPUT_BIN_DIR}")
 set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${CONFIG} "${OUTPUT_LIB_DIR}")
endforeach()

if(MSVC)
    add_compile_options(/arch:AVX2)
    add_compile_options(/utf-8)
else()
    add_compile_options(-Wall -Wextra)
    add_compile_options(-pedantic-errors)
    add_compile_options(-march=native)
endif()

find_package(Threads REQUIRED)

set(lib "${CMAKE_CURRENT_SOURCE_DIR}/libs")

if(WIN32)
    # Windows找 .lib 用于链接
    find_library(Z3_LIB NAMES libz3 z3 PATHS "${lib}" NO_DEFAULT_PATH)
    # .dll 用于运行时拷贝
    find_file(Z3_DLL NAMES libz3.dll PATHS "${lib}" NO_DEFAULT_PATH)
else()
    find_library(Z3_LIB NAMES z3 libz3 PATHS "${lib}" NO_DEFAULT_PATH)
endif()

if(NOT Z3_LIB)
    message(FATAL_ERROR "Z3 library not found in ${lib}! Please check filename.")
endif()

set(sourceDir "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(utilsDir "${sourceDir}/utils")
set(attackDir "${sourceDir}/Attack")

file(GLOB_RECURSE utilsSrc "${utilsDir}/*.cpp")
file(GLOB_RECURSE attackSrc "${attackDir}/*.cpp")

# --- Utils ---
add_library(utils STATIC ${utilsSrc})
target_include_directories(utils PUBLIC "include/utils")

# --- Attack ---
add_library(attack STATIC ${attackSrc})
target_include_directories(attack PUBLIC
        "include/Attack"
        "include/utils"
        "include/BlockCipher"
        "include/Z3"
)

# --- App ---
add_executable(app src/main.cpp)

target_include_directories(app PRIVATE "include/BlockCipher" "include/Attack")

target_link_libraries(app PRIVATE
        utils
        attack
        ${Z3_LIB}
        Threads::Threads
)

if(WIN32 AND Z3_DLL)
    add_custom_command(TARGET app POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${Z3_DLL}"
            "$<TARGET_FILE_DIR:app>"
            COMMENT "Copying libz3.dll to binary directory..."
    )
endif()
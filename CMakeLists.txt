# CMakeLists.txt
# Root C++20 & CUDA Build System for enclave-ai
# Author: Kamran Saberifard
# License: Apache 2.0

cmake_minimum_required(VERSION 3.20)

project(enclave-ai
    VERSION 0.1.0
    DESCRIPTION "Zero-Trust GPU Confidential Computing & Remote Attestation Engine"
    LANGUAGES CXX CUDA
)

# ------------------------------------------------------------------------------
# 1. C++ Standard & CUDA Architecture Flags
# ------------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Target Hopper (sm_90) and Blackwell (sm_100) GPU Confidential Compute
if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES 80 86 89 90)
endif()

add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wnon-virtual-dtor
    -Wnull-dereference
    -Wconversion
)

# ------------------------------------------------------------------------------
# 2. Find Dependencies (OpenSSL 3.0, CUDAToolkit, Protobuf, Threads)
# ------------------------------------------------------------------------------
find_package(OpenSSL 3.0 REQUIRED)
message(STATUS "[enclave-ai] Found OpenSSL: Version ${OPENSSL_VERSION}")

find_package(CUDAToolkit REQUIRED)
message(STATUS "[enclave-ai] Found CUDA Toolkit: Version ${CUDAToolkit_VERSION}")

find_package(Protobuf REQUIRED)
message(STATUS "[enclave-ai] Found Protobuf Compiler: ${Protobuf_PROTOC_EXECUTABLE}")

find_package(Threads REQUIRED)

# ------------------------------------------------------------------------------
# 3. Protobuf Code Generation
# ------------------------------------------------------------------------------
set(PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(PROTO_SRC_DIR ${CMAKE_BINARY_DIR}/proto_gen)
file(MAKE_DIRECTORY ${PROTO_SRC_DIR})

set(PROTO_FILES
    ${PROTO_DIR}/enclave/v1/attestation.proto
)

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS TARGET ${PROTO_FILES})

# ------------------------------------------------------------------------------
# 4. Core C++/CUDA Library Target (`enclave_core`)
# ------------------------------------------------------------------------------
file(GLOB_RECURSE ENCLAVE_CXX_SOURCES
    "src/*.cpp"
)

file(GLOB_RECURSE ENCLAVE_CUDA_SOURCES
    "cuda/*.cu"
)

add_library(enclave_core SHARED 
    ${ENCLAVE_CXX_SOURCES} 
    ${ENCLAVE_CUDA_SOURCES}
    ${PROTO_SRCS}
)

target_include_directories(enclave_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/proto_gen>
        ${OPENSSL_INCLUDE_DIR}
        ${CUDAToolkit_INCLUDE_DIRS}
        ${Protobuf_INCLUDE_DIRS}
)

target_link_libraries(enclave_core
    PUBLIC
        OpenSSL::Crypto
        OpenSSL::SSL
        CUDA::cudart
        CUDA::cuda_driver
        ${Protobuf_LIBRARIES}
        Threads::Threads
)

target_compile_definitions(enclave_core
    PRIVATE
        ENCLAVE_BUILD_INTERNAL=1
)

# ------------------------------------------------------------------------------
# 5. Executable Targets (`enclave-attest` & `enclave-run`)
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmd/enclave-attest/main.cpp")
    add_executable(enclave-attest cmd/enclave-attest/main.cpp)
    target_link_libraries(enclave-attest PRIVATE enclave_core)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmd/enclave-run/main.cpp")
    add_executable(enclave-run cmd/enclave-run/main.cpp)
    target_link_libraries(enclave-run PRIVATE enclave_core)
endif()

# ------------------------------------------------------------------------------
# 6. Unit Testing Targets
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    enable_testing()
    add_subdirectory(tests)
endif()
# tests/CMakeLists.txt
# Cryptographic & Hardware Security Unit Test Configuration for enclave-ai
# Author: Kamran Saberifard
# License: Apache 2.0

message(STATUS "[enclave-ai] Configuring Cryptographic & Hardware Security Unit Tests")

enable_testing()

# ------------------------------------------------------------------------------
# Test 1: SPDM 1.2 Hardware Remote Attestation Test
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_spdm_attestation.cpp")
    add_executable(test_spdm_attestation test_spdm_attestation.cpp)
    target_link_libraries(test_spdm_attestation PRIVATE enclave_core)
    add_test(NAME SPDMAttestationTest COMMAND test_spdm_attestation)
endif()

# ------------------------------------------------------------------------------
# Test 2: In-VRAM CUDA AES-256-GCM Tensor Decryption Test
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_encrypted_vram.cpp")
    add_executable(test_encrypted_vram test_encrypted_vram.cpp)
    target_link_libraries(test_encrypted_vram PRIVATE enclave_core)
    add_test(NAME EncryptedVRAMTest COMMAND test_encrypted_vram)
endif()

# ------------------------------------------------------------------------------
# Test 3: Zero-Trust Secure Allocator & VRAM Wiping Test
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_secure_allocator.cpp")
    add_executable(test_secure_allocator test_secure_allocator.cpp)
    target_link_libraries(test_secure_allocator PRIVATE enclave_core)
    add_test(NAME SecureAllocatorTest COMMAND test_secure_allocator)
endif()
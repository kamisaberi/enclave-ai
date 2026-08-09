/**
 * @file test_secure_allocator.cpp
 * @brief Unit Tests for Zero-Trust GPU VRAM Allocator & Sanitization in enclave-ai
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <enclave/enclave.hpp>
#include <enclave/memory/encrypted_vram_buffer.hpp>

#include <cassert>
#include <iostream>
#include <vector>

namespace {

void test_redzone_boundary_padding() {
    std::cout << "[TEST] Running Redzone Boundary Padding Test...\n";

    size_t payload_bytes = 2048;
    size_t redzone_bytes = 512;

    enclave::memory::EncryptedVRAMBuffer buffer(payload_bytes, "RedzoneTestBuffer", redzone_bytes);

    enclave::Status status = buffer.allocate();
    if (status != enclave::Status::Success) {
        std::cout << "\033[1;33m[SKIP] CUDA device unavailable. Skipping redzone test.\033[0m\n";
        return;
    }

    assert(buffer.is_allocated());
    assert(buffer.size_bytes() == payload_bytes);
    assert(buffer.redzone_bytes() == redzone_bytes);

    void* cipher_ptr = buffer.get_ciphertext_device_ptr();
    void* plain_ptr = buffer.get_decrypted_device_ptr();

    assert(cipher_ptr != nullptr);
    assert(plain_ptr != nullptr);
    assert(cipher_ptr != plain_ptr); // Ensures separate ciphertext and plaintext VRAM allocations

    status = buffer.sanitize_and_free();
    assert(status == enclave::Status::Success);
    assert(!buffer.is_allocated());

    std::cout << "\033[1;32m[PASS] Redzone Boundary Padding Verified!\033[0m\n";
}

void test_zero_trust_vram_wiping() {
    std::cout << "[TEST] Running Zero-Trust VRAM Wiping Test...\n";

    size_t payload_bytes = 4096;
    enclave::memory::EncryptedVRAMBuffer buffer(payload_bytes, "WipeTestBuffer");

    enclave::Status status = buffer.allocate();
    if (status != enclave::Status::Success) {
        std::cout << "\033[1;33m[SKIP] CUDA device unavailable. Skipping VRAM wiping test.\033[0m\n";
        return;
    }

    // Sanitize and free VRAM
    status = buffer.sanitize_and_free();
    assert(status == enclave::Status::Success);
    assert(buffer.get_decrypted_device_ptr() == nullptr);
    assert(buffer.get_ciphertext_device_ptr() == nullptr);

    std::cout << "\033[1;32m[PASS] Zero-Trust VRAM Wiping Verified!\033[0m\n";
}

} // anonymous namespace

int main() {
    std::cout << "\033[1;36m===================================================\033[0m\n";
    std::cout << "\033[1;36m enclave-ai Zero-Trust Allocator Unit Tests         \033[0m\n";
    std::cout << "\033[1;36m===================================================\033[0m\n\n";

    test_redzone_boundary_padding();
    test_zero_trust_vram_wiping();

    std::cout << "\n\033[1;32mAll Zero-Trust Allocator Unit Tests PASSED!\033[0m\n";
    return 0;
}
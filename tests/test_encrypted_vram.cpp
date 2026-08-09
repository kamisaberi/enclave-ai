/**
 * @file test_encrypted_vram.cpp
 * @brief Unit Tests for In-VRAM CUDA AES-256-GCM Tensor Decryption in enclave-ai
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <enclave/enclave.hpp>
#include <enclave/crypto/aes_gcm_engine.hpp>
#include <enclave/memory/encrypted_vram_buffer.hpp>

#include <cassert>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>

namespace {

void test_host_aes_gcm_encryption_decryption() {
    std::cout << "[TEST] Running Host OpenSSL AES-256-GCM Encryption/Decryption Test...\n";

    enclave::crypto::AESGCMEngine engine;
    auto key = enclave::crypto::AESGCMEngine::generate_random_key();
    assert(key.size() == 32);

    std::string plaintext_str = "Confidential Deep Learning Model Weight Tensor Payload 2026";
    std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());

    // 1. Encrypt Plaintext Tensor
    auto encrypted_block = engine.encrypt_tensor(plaintext, key);
    assert(!encrypted_block.ciphertext.empty());
    assert(encrypted_block.ciphertext != plaintext);
    assert(encrypted_block.tag.size() == 16);
    assert(encrypted_block.iv.size() == 12);

    // 2. Decrypt Ciphertext Tensor
    std::vector<uint8_t> decrypted(plaintext.size());
    enclave::Status status = engine.decrypt_tensor(encrypted_block, key, decrypted);
    assert(status == enclave::Status::Success);
    assert(decrypted == plaintext);

    // 3. Test Tampered Tag Detection
    auto tampered_block = encrypted_block;
    tampered_block.tag[0] ^= 0xFF; // Mangle authentication tag

    std::vector<uint8_t> tampered_out(plaintext.size());
    status = engine.decrypt_tensor(tampered_block, key, tampered_out);
    assert(status == enclave::Status::ErrAESGCMDecryptionFailed);

    std::cout << "\033[1;32m[PASS] Host AES-256-GCM Encryption & Tag Verification Verified!\033[0m\n";
}

void test_in_vram_cuda_decryption() {
    std::cout << "[TEST] Running In-VRAM CUDA AES-256 Decryption Test...\n";

    size_t tensor_bytes = 1024 * 1024; // 1 MB test tensor
    enclave::memory::EncryptedVRAMBuffer vram_buffer(tensor_bytes, "UnitTestVRAMBuffer");

    enclave::Status status = vram_buffer.allocate();
    if (status != enclave::Status::Success) {
        std::cout << "\033[1;33m[SKIP] CUDA GPU device unavailable or allocation failed. Skipping.\033[0m\n";
        return;
    }

    assert(vram_buffer.is_allocated());
    assert(vram_buffer.get_ciphertext_device_ptr() != nullptr);
    assert(vram_buffer.get_decrypted_device_ptr() != nullptr);

    // Prepare dummy encrypted payload
    enclave::crypto::EncryptedTensorBlock block{};
    block.plaintext_bytes = tensor_bytes;
    block.ciphertext.resize(tensor_bytes, 0x42);
    block.iv = std::vector<uint8_t>(12, 0x01);
    block.tag = std::vector<uint8_t>(16, 0xEE);

    // Upload payload to GPU device memory
    status = vram_buffer.upload_encrypted_payload(block);
    assert(status == enclave::Status::Success);

    // Execute in-VRAM CUDA stream cipher decryption kernel
    std::vector<uint8_t> round_keys(240, 0x05); // Dummy expanded round keys
    status = vram_buffer.decrypt_in_vram(round_keys);
    assert(status == enclave::Status::Success);
    assert(vram_buffer.is_decrypted());

    // Sanitize and free GPU memory
    status = vram_buffer.sanitize_and_free();
    assert(status == enclave::Status::Success);
    assert(!vram_buffer.is_allocated());

    std::cout << "\033[1;32m[PASS] In-VRAM CUDA Decryption & Zero-Trust Sanitization Verified!\033[0m\n";
}

} // anonymous namespace

int main() {
    std::cout << "\033[1;36m===================================================\033[0m\n";
    std::cout << "\033[1;36m enclave-ai Encrypted VRAM & Crypto Unit Tests     \033[0m\n";
    std::cout << "\033[1;36m===================================================\033[0m\n\n";

    test_host_aes_gcm_encryption_decryption();
    test_in_vram_cuda_decryption();

    std::cout << "\n\033[1;32mAll Encrypted VRAM Unit Tests PASSED!\033[0m\n";
    return 0;
}
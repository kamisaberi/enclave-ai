/**
 * @file encrypted_vram_buffer.cpp
 * @brief Zero-Trust Encrypted GPU VRAM Buffer Manager Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <enclave/memory/encrypted_vram_buffer.hpp>

#include <cuda_runtime.h>
#include <iostream>
#include <format>
#include <cstring>
#include <utility>

namespace enclave::memory {

EncryptedVRAMBuffer::EncryptedVRAMBuffer(size_t size_bytes, std::string_view label, size_t redzone_bytes)
    : m_payload_bytes(size_bytes),
      m_redzone_bytes(redzone_bytes),
      m_label(label) {}

EncryptedVRAMBuffer::~EncryptedVRAMBuffer() {
    sanitize_and_free();
}

EncryptedVRAMBuffer::EncryptedVRAMBuffer(EncryptedVRAMBuffer&& other) noexcept {
    std::lock_guard<std::mutex> lock(other.m_mutex);

    m_payload_bytes = other.m_payload_bytes;
    m_redzone_bytes = other.m_redzone_bytes;
    m_label = std::move(other.m_label);

    m_raw_ciphertext_ptr = other.m_raw_ciphertext_ptr;
    m_usable_ciphertext_ptr = other.m_usable_ciphertext_ptr;
    m_raw_plaintext_ptr = other.m_raw_plaintext_ptr;
    m_usable_plaintext_ptr = other.m_usable_plaintext_ptr;
    m_device_iv_ptr = other.m_device_iv_ptr;

    m_is_allocated = other.m_is_allocated;
    m_is_decrypted = other.m_is_decrypted;

    other.m_raw_ciphertext_ptr = nullptr;
    other.m_usable_ciphertext_ptr = nullptr;
    other.m_raw_plaintext_ptr = nullptr;
    other.m_usable_plaintext_ptr = nullptr;
    other.m_device_iv_ptr = nullptr;
    other.m_is_allocated = false;
    other.m_is_decrypted = false;
}

EncryptedVRAMBuffer& EncryptedVRAMBuffer::operator=(EncryptedVRAMBuffer&& other) noexcept {
    if (this != &other) {
        sanitize_and_free();

        std::lock_guard<std::mutex> lock_this(m_mutex);
        std::lock_guard<std::mutex> lock_other(other.m_mutex);

        m_payload_bytes = other.m_payload_bytes;
        m_redzone_bytes = other.m_redzone_bytes;
        m_label = std::move(other.m_label);

        m_raw_ciphertext_ptr = other.m_raw_ciphertext_ptr;
        m_usable_ciphertext_ptr = other.m_usable_ciphertext_ptr;
        m_raw_plaintext_ptr = other.m_raw_plaintext_ptr;
        m_usable_plaintext_ptr = other.m_usable_plaintext_ptr;
        m_device_iv_ptr = other.m_device_iv_ptr;

        m_is_allocated = other.m_is_allocated;
        m_is_decrypted = other.m_is_decrypted;

        other.m_raw_ciphertext_ptr = nullptr;
        other.m_usable_ciphertext_ptr = nullptr;
        other.m_raw_plaintext_ptr = nullptr;
        other.m_usable_plaintext_ptr = nullptr;
        other.m_device_iv_ptr = nullptr;
        other.m_is_allocated = false;
        other.m_is_decrypted = false;
    }
    return *this;
}

Status EncryptedVRAMBuffer::allocate() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_is_allocated) {
        return Status::Success; // Already allocated
    }

    if (m_payload_bytes == 0) {
        return Status::ErrEncryptedVRAMAllocationFailed;
    }

    size_t total_allocation_bytes = m_payload_bytes + (m_redzone_bytes * 2);

    // 1. Allocate Raw Ciphertext VRAM Buffer
    cudaError_t err = cudaMalloc(&m_raw_ciphertext_ptr, total_allocation_bytes);
    if (err != cudaSuccess) {
        return Status::ErrEncryptedVRAMAllocationFailed;
    }

    // 2. Allocate Raw Plaintext VRAM Buffer
    err = cudaMalloc(&m_raw_plaintext_ptr, total_allocation_bytes);
    if (err != cudaSuccess) {
        cudaFree(m_raw_ciphertext_ptr);
        m_raw_ciphertext_ptr = nullptr;
        return Status::ErrEncryptedVRAMAllocationFailed;
    }

    // 3. Allocate Device IV Buffer (12 bytes)
    err = cudaMalloc(&m_device_iv_ptr, crypto::AES_GCM_IV_SIZE);
    if (err != cudaSuccess) {
        cudaFree(m_raw_ciphertext_ptr);
        cudaFree(m_raw_plaintext_ptr);
        m_raw_ciphertext_ptr = nullptr;
        m_raw_plaintext_ptr = nullptr;
        return Status::ErrEncryptedVRAMAllocationFailed;
    }

    // Zero out device buffers including redzone guard bands
    cudaMemset(m_raw_ciphertext_ptr, 0, total_allocation_bytes);
    cudaMemset(m_raw_plaintext_ptr, 0, total_allocation_bytes);
    cudaMemset(m_device_iv_ptr, 0, crypto::AES_GCM_IV_SIZE);

    // Compute usable pointers offset past front redzones
    uintptr_t raw_cipher_addr = reinterpret_cast<uintptr_t>(m_raw_ciphertext_ptr);
    uintptr_t raw_plain_addr = reinterpret_cast<uintptr_t>(m_raw_plaintext_ptr);

    m_usable_ciphertext_ptr = reinterpret_cast<void*>(raw_cipher_addr + m_redzone_bytes);
    m_usable_plaintext_ptr = reinterpret_cast<void*>(raw_plain_addr + m_redzone_bytes);

    m_is_allocated = true;
    m_is_decrypted = false;

    return Status::Success;
}

Status EncryptedVRAMBuffer::upload_encrypted_payload(const crypto::EncryptedTensorBlock& block) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_is_allocated) {
        return Status::ErrEncryptedVRAMAllocationFailed;
    }

    if (block.ciphertext.size() != m_payload_bytes || block.iv.size() != crypto::AES_GCM_IV_SIZE) {
        return Status::ErrEncryptedVRAMAllocationFailed; // Size mismatch
    }

    // Copy IV to GPU device memory
    cudaError_t err = cudaMemcpy(m_device_iv_ptr, block.iv.data(), crypto::AES_GCM_IV_SIZE, cudaMemcpyHostToDevice);
    if (err != cudaSuccess) return Status::ErrEncryptedVRAMAllocationFailed;

    // Copy Ciphertext payload to GPU device memory (into usable payload area)
    err = cudaMemcpy(m_usable_ciphertext_ptr, block.ciphertext.data(), m_payload_bytes, cudaMemcpyHostToDevice);
    if (err != cudaSuccess) return Status::ErrEncryptedVRAMAllocationFailed;

    m_is_decrypted = false;
    return Status::Success;
}

Status EncryptedVRAMBuffer::decrypt_in_vram(std::span<const uint8_t> round_keys, cudaStream_t stream) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_is_allocated) {
        return Status::ErrEncryptedVRAMAllocationFailed;
    }

    if (round_keys.size() != 240) { // 240 bytes = 15 round keys for AES-256
        return Status::ErrAESGCMDecryptionFailed;
    }

    // Launch CUDA kernel for in-VRAM parallel stream cipher decryption
    cudaError_t err = cuda_launch_aes256_decrypt(
        static_cast<const uint8_t*>(m_usable_ciphertext_ptr),
        static_cast<uint8_t*>(m_usable_plaintext_ptr),
        static_cast<const uint8_t*>(m_device_iv_ptr),
        round_keys.data(),
        m_payload_bytes,
        stream
    );

    if (err != cudaSuccess) {
        std::cerr << std::format("[ENCLAVE-MEMORY-ERROR] CUDA in-VRAM decryption kernel launch failed: {}\n", 
                                  cudaGetErrorString(err));
        return Status::ErrAESGCMDecryptionFailed;
    }

    m_is_decrypted = true;
    return Status::Success;
}

Status EncryptedVRAMBuffer::sanitize_and_free() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_is_allocated) {
        return Status::Success;
    }

    size_t total_allocation_bytes = m_payload_bytes + (m_redzone_bytes * 2);

    // Zero-trust parallel GPU memory sanitization using CUDA zeroing kernel
    if (m_raw_ciphertext_ptr) {
        cuda_launch_zero_vram(m_raw_ciphertext_ptr, total_allocation_bytes, nullptr);
        cudaFree(m_raw_ciphertext_ptr);
        m_raw_ciphertext_ptr = nullptr;
        m_usable_ciphertext_ptr = nullptr;
    }

    if (m_raw_plaintext_ptr) {
        cuda_launch_zero_vram(m_raw_plaintext_ptr, total_allocation_bytes, nullptr);
        cudaFree(m_raw_plaintext_ptr);
        m_raw_plaintext_ptr = nullptr;
        m_usable_plaintext_ptr = nullptr;
    }

    if (m_device_iv_ptr) {
        cuda_launch_zero_vram(m_device_iv_ptr, crypto::AES_GCM_IV_SIZE, nullptr);
        cudaFree(m_device_iv_ptr);
        m_device_iv_ptr = nullptr;
    }

    m_is_allocated = false;
    m_is_decrypted = false;

    return Status::Success;
}

} // namespace enclave::memory
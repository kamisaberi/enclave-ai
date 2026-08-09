/**
 * @file encrypted_vram_buffer.hpp
 * @brief Zero-Trust Encrypted GPU VRAM Buffer Manager Header for enclave-ai
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <enclave/enclave.hpp>
#include <enclave/crypto/aes_gcm_engine.hpp>

#include <cuda_runtime.h>

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <memory>
#include <mutex>
#include <span>

// C Linkage declarations for CUDA launcher functions defined in cuda/aes_gcm_kernel.cu
extern "C" {
    cudaError_t cuda_launch_aes256_decrypt(
        const uint8_t* d_ciphertext,
        uint8_t* d_plaintext,
        const uint8_t* d_iv,
        const uint8_t* host_round_keys,
        size_t num_bytes,
        cudaStream_t stream
    );

    cudaError_t cuda_launch_zero_vram(
        void* d_ptr,
        size_t num_bytes,
        cudaStream_t stream
    );
}

namespace enclave::memory {

/**
 * @brief RAII Manager for protected, encrypted GPU VRAM buffers inside GPU TEE enclaves.
 */
class ENCLAVE_API EncryptedVRAMBuffer {
public:
    explicit EncryptedVRAMBuffer(
        size_t size_bytes, 
        std::string_view label = "unlabeled_encrypted_vram", 
        size_t redzone_bytes = 256
    );
    ~EncryptedVRAMBuffer();

    // Non-copyable
    EncryptedVRAMBuffer(const EncryptedVRAMBuffer&) = delete;
    EncryptedVRAMBuffer& operator=(const EncryptedVRAMBuffer&) = delete;

    // Movable
    EncryptedVRAMBuffer(EncryptedVRAMBuffer&& other) noexcept;
    EncryptedVRAMBuffer& operator=(EncryptedVRAMBuffer&& other) noexcept;

    /**
     * @brief Allocates GPU device memory for ciphertext and plaintext buffers with redzones.
     * @return Status::Success if VRAM allocated and redzones zeroed out.
     */
    Status allocate();

    /**
     * @brief Uploads an encrypted tensor block (IV, tag, ciphertext) to GPU device memory.
     * @param block Encrypted tensor block structure.
     * @return Status::Success if memory copied to GPU VRAM.
     */
    Status upload_encrypted_payload(const crypto::EncryptedTensorBlock& block);

    /**
     * @brief Executes in-VRAM parallel CUDA AES-256 stream decryption directly on GPU hardware.
     * @param round_keys 240-byte AES-256 expanded round keys buffer.
     * @param stream Optional CUDA stream handle for asynchronous execution.
     * @return Status::Success if CUDA kernel launched and executed without error.
     */
    Status decrypt_in_vram(std::span<const uint8_t> round_keys, cudaStream_t stream = nullptr);

    /**
     * @brief Performs parallel CUDA zeroing (`explicit_bzero` for VRAM) and frees device memory.
     * @return Status::Success if memory sanitized and freed.
     */
    Status sanitize_and_free() noexcept;

    // -------------------------------------------------------------------------
    // Getters & Pointers
    // -------------------------------------------------------------------------

    /**
     * @brief Returns the raw device pointer to the decrypted tensor payload inside GPU VRAM.
     */
    [[nodiscard]] void* get_decrypted_device_ptr() const noexcept { return m_usable_plaintext_ptr; }

    /**
     * @brief Returns the raw device pointer to the encrypted ciphertext buffer inside GPU VRAM.
     */
    [[nodiscard]] void* get_ciphertext_device_ptr() const noexcept { return m_usable_ciphertext_ptr; }

    [[nodiscard]] size_t size_bytes() const noexcept { return m_payload_bytes; }
    [[nodiscard]] size_t redzone_bytes() const noexcept { return m_redzone_bytes; }
    [[nodiscard]] std::string_view label() const noexcept { return m_label; }
    [[nodiscard]] bool is_allocated() const noexcept { return m_is_allocated; }
    [[nodiscard]] bool is_decrypted() const noexcept { return m_is_decrypted; }

private:
    size_t m_payload_bytes{0};
    size_t m_redzone_bytes{256};
    std::string m_label;

    void* m_raw_ciphertext_ptr{nullptr};
    void* m_usable_ciphertext_ptr{nullptr};
    void* m_raw_plaintext_ptr{nullptr};
    void* m_usable_plaintext_ptr{nullptr};
    void* m_device_iv_ptr{nullptr};

    bool m_is_allocated{false};
    bool m_is_decrypted{false};
    mutable std::mutex m_mutex;
};

} // namespace enclave::memory
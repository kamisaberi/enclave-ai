/**
 * @file aes_gcm_engine.hpp
 * @brief High-Throughput AES-256-GCM Tensor Stream Cipher Engine Header for enclave-ai
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <enclave/enclave.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdint>
#include <vector>
#include <memory>
#include <mutex>
#include <span>

namespace enclave::crypto {

/**
 * @brief Standard Cryptographic Key & Tag Constants for AES-256-GCM
 */
constexpr size_t AES_256_KEY_SIZE = 32; // 256 bits
constexpr size_t AES_GCM_IV_SIZE  = 12; // 96 bits
constexpr size_t AES_GCM_TAG_SIZE = 16; // 128 bits

/**
 * @brief Container holding an encrypted tensor payload with its IV and authentication tag.
 */
struct ENCLAVE_API EncryptedTensorBlock {
    std::vector<uint8_t> iv;          // 12-byte random IV
    std::vector<uint8_t> tag;         // 16-byte GCM authentication tag
    std::vector<uint8_t> ciphertext;  // Encrypted tensor bytes
    size_t plaintext_bytes{0};
};

/**
 * @brief Thread-Safe OpenSSL 3.x AES-256-GCM Tensor Stream Cipher Engine.
 */
class ENCLAVE_API AESGCMEngine {
public:
    AESGCMEngine();
    ~AESGCMEngine();

    // Non-copyable, non-movable (RAII OpenSSL EVP_CIPHER_CTX pointer management)
    AESGCMEngine(const AESGCMEngine&) = delete;
    AESGCMEngine& operator=(const AESGCMEngine&) = delete;
    AESGCMEngine(AESGCMEngine&&) = delete;
    AESGCMEngine& operator=(AESGCMEngine&&) = delete;

    /**
     * @brief Generates a cryptographically secure 256-bit (32-byte) random secret key using OpenSSL RAND_bytes.
     * @return 32-byte vector containing the generated key.
     */
    [[nodiscard]] static std::vector<uint8_t> generate_random_key();

    /**
     * @brief Generates a cryptographically secure 96-bit (12-byte) random IV.
     * @return 12-byte vector containing the generated IV.
     */
    [[nodiscard]] static std::vector<uint8_t> generate_random_iv();

    /**
     * @brief Encrypts a raw model weight tensor buffer using AES-256-GCM.
     * @param plaintext Input unencrypted tensor byte span.
     * @param key 32-byte secret encryption key.
     * @return EncryptedTensorBlock containing IV, ciphertext, and 16-byte auth tag.
     * @throws EnclaveException if encryption fails.
     */
    [[nodiscard]] EncryptedTensorBlock encrypt_tensor(
        std::span<const uint8_t> plaintext, 
        std::span<const uint8_t> key
    ) const;

    /**
     * @brief Decrypts an EncryptedTensorBlock payload into a target plaintext buffer.
     * @param encrypted_block Block containing IV, tag, and ciphertext.
     * @param key 32-byte secret encryption key.
     * @param out_plaintext Output buffer to receive decrypted tensor bytes.
     * @return Status::Success if tag verified and data decrypted; ErrAESGCMDecryptionFailed if tampered.
     */
    Status decrypt_tensor(
        const EncryptedTensorBlock& encrypted_block,
        std::span<const uint8_t> key,
        std::span<uint8_t> out_plaintext
    ) const;

    /**
     * @brief Zero-copy span-based AES-256-GCM tensor decryption API.
     * @param ciphertext Raw encrypted tensor bytes.
     * @param iv 12-byte initialization vector.
     * @param tag 16-byte authentication tag.
     * @param key 32-byte secret key.
     * @param out_plaintext Output target buffer.
     * @return Status::Success if authentication tag verified and plaintext extracted.
     */
    Status decrypt_tensor_raw(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> iv,
        std::span<const uint8_t> tag,
        std::span<const uint8_t> key,
        std::span<uint8_t> out_plaintext
    ) const;

private:
    mutable std::mutex m_mutex;
    EVP_CIPHER_CTX* m_cipher_ctx{nullptr};
};

} // namespace enclave::crypto
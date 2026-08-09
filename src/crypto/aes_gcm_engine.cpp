/**
 * @file aes_gcm_engine.cpp
 * @brief High-Throughput AES-256-GCM Tensor Stream Cipher Engine Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <enclave/crypto/aes_gcm_engine.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <iostream>
#include <format>
#include <cstring>

namespace enclave::crypto {

AESGCMEngine::AESGCMEngine() {
    m_cipher_ctx = EVP_CIPHER_CTX_new();
}

AESGCMEngine::~AESGCMEngine() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_cipher_ctx) {
        EVP_CIPHER_CTX_free(m_cipher_ctx);
        m_cipher_ctx = nullptr;
    }
}

std::vector<uint8_t> AESGCMEngine::generate_random_key() {
    std::vector<uint8_t> key(AES_256_KEY_SIZE);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        throw EnclaveException(Status::ErrAESGCMDecryptionFailed, "Failed to generate cryptographically secure 256-bit AES key.");
    }
    return key;
}

std::vector<uint8_t> AESGCMEngine::generate_random_iv() {
    std::vector<uint8_t> iv(AES_GCM_IV_SIZE);
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        throw EnclaveException(Status::ErrAESGCMDecryptionFailed, "Failed to generate cryptographically secure 96-bit AES IV.");
    }
    return iv;
}

EncryptedTensorBlock AESGCMEngine::encrypt_tensor(
    std::span<const uint8_t> plaintext, 
    std::span<const uint8_t> key
) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (key.size() != AES_256_KEY_SIZE) {
        throw EnclaveException(Status::ErrAESGCMDecryptionFailed, "AES-256-GCM requires a 32-byte (256-bit) key.");
    }

    if (!m_cipher_ctx) {
        throw EnclaveException(Status::ErrAESGCMDecryptionFailed, "OpenSSL EVP Cipher Context is uninitialized.");
    }

    EVP_CIPHER_CTX_reset(m_cipher_ctx);

    EncryptedTensorBlock block{};
    block.iv = generate_random_iv();
    block.tag.resize(AES_GCM_TAG_SIZE);
    block.ciphertext.resize(plaintext.size());
    block.plaintext_bytes = plaintext.size();

    // 1. Initialize Encryption Context with AES-256-GCM
    if (EVP_EncryptInit_ex(m_cipher_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw EnclaveException(Status::ErrAESGCMDecryptionFailed, "EVP_EncryptInit_ex failed.");
    }

    // 2. Set IV length to 12 bytes (96 bits)
    if (EVP_CIPHER_CTX_ctrl(m_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(AES_GCM_IV_SIZE), nullptr) != 1) {
        throw EnclaveException(Status::ErrAESGCMDecryptionFailed, "Failed to set GCM IV length.");
    }

    // 3. Initialize Key and IV
    if (EVP_EncryptInit_ex(m_cipher_ctx, nullptr, nullptr, key.data(), block.iv.data()) != 1) {
        throw EnclaveException(Status::ErrAESGCMDecryptionFailed, "Failed to initialize Key and IV.");
    }

    // 4. Perform Stream Encryption
    int out_len = 0;
    if (EVP_EncryptUpdate(m_cipher_ctx, block.ciphertext.data(), &out_len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        throw EnclaveException(Status::ErrAESGCMDecryptionFailed, "EVP_EncryptUpdate failed.");
    }
    int total_len = out_len;

    // 5. Finalize Encryption
    if (EVP_EncryptFinal_ex(m_cipher_ctx, block.ciphertext.data() + total_len, &out_len) != 1) {
        throw EnclaveException(Status::ErrAESGCMDecryptionFailed, "EVP_EncryptFinal_ex failed.");
    }

    // 6. Extract 16-byte GCM Authentication Tag
    if (EVP_CIPHER_CTX_ctrl(m_cipher_ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(AES_GCM_TAG_SIZE), block.tag.data()) != 1) {
        throw EnclaveException(Status::ErrAESGCMDecryptionFailed, "Failed to extract GCM authentication tag.");
    }

    return block;
}

Status AESGCMEngine::decrypt_tensor(
    const EncryptedTensorBlock& encrypted_block,
    std::span<const uint8_t> key,
    std::span<uint8_t> out_plaintext
) const {
    return decrypt_tensor_raw(
        encrypted_block.ciphertext,
        encrypted_block.iv,
        encrypted_block.tag,
        key,
        out_plaintext
    );
}

Status AESGCMEngine::decrypt_tensor_raw(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> iv,
    std::span<const uint8_t> tag,
    std::span<const uint8_t> key,
    std::span<uint8_t> out_plaintext
) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (key.size() != AES_256_KEY_SIZE || iv.size() != AES_GCM_IV_SIZE || tag.size() != AES_GCM_TAG_SIZE) {
        return Status::ErrAESGCMDecryptionFailed;
    }

    if (out_plaintext.size() < ciphertext.size()) {
        return Status::ErrAESGCMDecryptionFailed; // Output target buffer too small
    }

    if (!m_cipher_ctx) {
        return Status::ErrAESGCMDecryptionFailed;
    }

    EVP_CIPHER_CTX_reset(m_cipher_ctx);

    // 1. Initialize Decryption Context with AES-256-GCM
    if (EVP_DecryptInit_ex(m_cipher_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return Status::ErrAESGCMDecryptionFailed;
    }

    // 2. Set IV length
    if (EVP_CIPHER_CTX_ctrl(m_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
        return Status::ErrAESGCMDecryptionFailed;
    }

    // 3. Initialize Key and IV
    if (EVP_DecryptInit_ex(m_cipher_ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        return Status::ErrAESGCMDecryptionFailed;
    }

    // 4. Perform Decryption Update
    int out_len = 0;
    if (EVP_DecryptUpdate(m_cipher_ctx, out_plaintext.data(), &out_len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        return Status::ErrAESGCMDecryptionFailed;
    }

    // 5. Set Expected GCM Tag for Verification
    if (EVP_CIPHER_CTX_ctrl(m_cipher_ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data())) != 1) {
        return Status::ErrAESGCMDecryptionFailed;
    }

    // 6. Verify Tag and Finalize Decryption
    int final_len = 0;
    int ret = EVP_DecryptFinal_ex(m_cipher_ctx, out_plaintext.data() + out_len, &final_len);

    if (ret <= 0) {
        // Tag verification failed! Payload was tampered with or key was incorrect.
        std::cerr << "[ENCLAVE-CRYPTO-ALERT] AES-256-GCM Tag Verification Failed! Payload Tampering Detected.\n";
        std::memset(out_plaintext.data(), 0, out_plaintext.size()); // Zero-out output memory
        return Status::ErrAESGCMDecryptionFailed;
    }

    return Status::Success;
}

} // namespace enclave::crypto
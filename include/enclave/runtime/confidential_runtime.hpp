/**
 * @file confidential_runtime.hpp
 * @brief Zero-Trust Confidential GPU Execution Runtime Header for enclave-ai
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <enclave/enclave.hpp>
#include <enclave/attestation/spdm_verifier.hpp>
#include <enclave/crypto/aes_gcm_engine.hpp>
#include <enclave/memory/encrypted_vram_buffer.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <optional>
#include <filesystem>
#include <chrono>
#include <span>

namespace enclave::runtime {

/**
 * @brief Configuration parameters for instantiating a Confidential Model Runtime.
 */
struct ENCLAVE_API ConfidentialModelConfig {
    std::string model_id;
    HardwareTarget target_hardware{HardwareTarget::NVIDIA_Hopper_H100};
    std::filesystem::path root_ca_cert_path{"certs/nvidia_root_ca.pem"};
    std::filesystem::path expected_rim_path{"certs/sample_rim_profile.json"};
    size_t max_vram_allocation_bytes{16ULL * 1024ULL * 1024ULL * 1024ULL}; // 16 GB default
};

/**
 * @brief Result payload returned after executing confidential model inference.
 */
struct ENCLAVE_API InferenceResult {
    std::string model_id;
    bool success{false};
    std::vector<uint8_t> output_tensor_data;
    double attestation_time_ms{0.0};
    double decryption_time_ms{0.0};
    double execution_time_ms{0.0};
    std::string status_message;
};

/**
 * @brief Thread-Safe Confidential AI Execution Runtime Orchestrator.
 */
class ENCLAVE_API ConfidentialRuntime {
public:
    ConfidentialRuntime();
    ~ConfidentialRuntime();

    // Non-copyable, non-movable
    ConfidentialRuntime(const ConfidentialRuntime&) = delete;
    ConfidentialRuntime& operator=(const ConfidentialRuntime&) = delete;
    ConfidentialRuntime(ConfidentialRuntime&&) = delete;
    ConfidentialRuntime& operator=(ConfidentialRuntime&&) = delete;

    /**
     * @brief Initializes the runtime with target hardware configurations and loads Root CAs.
     * @param config Model runtime configuration struct.
     * @return Status::Success if SPDM verifier initialized.
     */
    Status init(const ConfidentialModelConfig& config);

    /**
     * @brief Verifies the GPU TEE's SPDM 1.2 attestation quote before allowing model loading.
     * @param quote The attestation quote payload received from the GPU Security Processor (GSP).
     * @param client_nonce Original 32-byte client challenge nonce.
     * @return Status::Success if quote, certificate chain, and RIM hashes are authentic.
     */
    Status verify_attestation(
        const attestation::AttestationQuote& quote, 
        std::span<const uint8_t> client_nonce
    );

    /**
     * @brief Uploads an encrypted model tensor block into protected VRAM and decrypts in-place.
     * @param encrypted_block AES-256-GCM encrypted tensor payload.
     * @param round_keys 240-byte AES-256 expanded round keys.
     * @return Status::Success if memory allocated and decrypted in VRAM.
     */
    Status load_encrypted_model(
        const crypto::EncryptedTensorBlock& encrypted_block, 
        std::span<const uint8_t> round_keys
    );

    /**
     * @brief Executes inference on the decrypted VRAM tensor buffers inside the GPU TEE.
     * @param input_tensor Raw input tensor bytes (e.g., token embeddings or prompt image).
     * @return InferenceResult containing output tensor payload and performance breakdown.
     */
    [[nodiscard]] InferenceResult execute_inference(std::span<const uint8_t> input_tensor);

    /**
     * @brief Sanitizes (zero-fills) all protected VRAM buffers and unloads model memory.
     */
    void sanitize_and_unload() noexcept;

    /**
     * @brief Returns the current status summary of the confidential enclave.
     */
    [[nodiscard]] EnclaveStatusSummary get_status_summary() const noexcept;

    [[nodiscard]] bool is_attested() const noexcept { return m_attestation_verified; }
    [[nodiscard]] bool is_model_loaded() const noexcept { return m_model_loaded; }

private:
    ConfidentialModelConfig m_config{};
    std::unique_ptr<attestation::SPDMVerifier> m_spdm_verifier;
    std::unique_ptr<memory::EncryptedVRAMBuffer> m_vram_buffer;

    bool m_initialized{false};
    bool m_attestation_verified{false};
    bool m_model_loaded{false};

    mutable std::mutex m_mutex;
};

} // namespace enclave::runtime
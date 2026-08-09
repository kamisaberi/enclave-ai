/**
 * @file spdm_verifier.hpp
 * @brief SPDM 1.2 Hardware Remote Attestation Verifier Header for enclave-ai
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <enclave/enclave.hpp>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <memory>
#include <optional>
#include <mutex>
#include <span>

namespace enclave::attestation {

/**
 * @brief Reference Integrity Measurement (RIM) profile hash container.
 */
struct ENCLAVE_API RIMProfile {
    std::string driver_version;         // e.g., "550.54.14"
    std::string vbios_version;          // GPU VBIOS version
    std::vector<uint8_t> driver_rim_hash;         // SHA-256 hash of GPU driver
    std::vector<uint8_t> gsp_firmware_rim_hash;   // SHA-256 hash of NVIDIA GSP firmware
    std::vector<uint8_t> kernel_module_rim_hash; // SHA-256 hash of nvidia-uvm kernel modules
};

/**
 * @brief Structure holding a complete SPDM 1.2 attestation quote payload.
 */
struct ENCLAVE_API AttestationQuote {
    std::string challenge_id;
    HardwareTarget target_hardware{HardwareTarget::NVIDIA_Hopper_H100};
    std::vector<uint8_t> client_nonce;            // 32-byte client challenge nonce
    std::vector<uint8_t> gsp_nonce;               // 32-byte GSP random nonce
    std::vector<uint8_t> measurement_summary;     // SHA-256 digest over SPDM measurement blocks
    RIMProfile active_rim_profile;                // Measured RIM hashes from GPU GSP
    std::vector<uint8_t> gsp_signature;           // ECDSA signature signed by GPU Leaf Private Key
    std::vector<uint8_t> certificate_chain_der;   // DER-encoded x509 cert chain signed by Root CA
    int64_t timestamp_ns{0};
};

/**
 * @brief Detailed verification report returned after checking an AttestationQuote.
 */
struct ENCLAVE_API VerificationResult {
    bool is_valid{false};
    bool cert_chain_valid{false};
    bool rim_matched{false};
    bool signature_valid{false};
    bool nonce_matched{false};
    std::string error_message;
};

/**
 * @brief Thread-Safe SPDM 1.2 Hardware Remote Attestation Verifier.
 */
class ENCLAVE_API SPDMVerifier {
public:
    SPDMVerifier();
    ~SPDMVerifier();

    // Non-copyable, non-movable (RAII around OpenSSL X509_STORE pointers)
    SPDMVerifier(const SPDMVerifier&) = delete;
    SPDMVerifier& operator=(const SPDMVerifier&) = delete;
    SPDMVerifier(SPDMVerifier&&) = delete;
    SPDMVerifier& operator=(SPDMVerifier&&) = delete;

    /**
     * @brief Loads and trusts the official NVIDIA Root CA certificate.
     * @param cert_pem_path Path to the NVIDIA Root CA certificate file (PEM format).
     * @return Status::Success if Root CA certificate was loaded into OpenSSL store.
     */
    Status load_root_ca(const std::filesystem::path& cert_pem_path);

    /**
     * @brief Loads expected Reference Integrity Measurement (RIM) hash baseline from JSON.
     * @param rim_json_path Path to expected RIM profile JSON.
     * @return Status::Success if RIM baseline loaded.
     */
    Status load_expected_rim_profile(const std::filesystem::path& rim_json_path);

    /**
     * @brief Verifies an SPDM 1.2 AttestationQuote against Root CA and expected RIM baseline.
     * @param quote The attestation quote payload received from the GPU node.
     * @param expected_client_nonce Original 32-byte client challenge nonce.
     * @return VerificationResult containing detailed validation flags.
     */
    [[nodiscard]] VerificationResult verify_quote(
        const AttestationQuote& quote, 
        std::span<const uint8_t> expected_client_nonce
    ) const;

    /**
     * @brief Validates a DER-encoded x509 certificate chain against trusted Root CA store.
     * @param cert_chain_der DER-encoded binary certificate chain.
     * @param out_leaf_pubkey Pointer to receive extracted Leaf Public Key if valid.
     * @return Status::Success if certificate chain is authentic and untampered.
     */
    Status verify_certificate_chain(std::span<const uint8_t> cert_chain_der, EVP_PKEY** out_leaf_pubkey) const;

    /**
     * @brief Verifies ECDSA signature over the attestation quote measurement digest using Leaf Public Key.
     * @param quote Attestation quote struct.
     * @param leaf_pubkey Validated GPU Leaf Public Key extracted from cert chain.
     * @return Status::Success if cryptographic signature is valid.
     */
    Status verify_signature(const AttestationQuote& quote, EVP_PKEY* leaf_pubkey) const;

    /**
     * @brief Compares measured RIM profile hashes against expected hardware baseline.
     * @param measured_rim RIM profile reported by GPU Security Processor.
     * @return Status::Success if all SHA-256 RIM hashes match expected baseline.
     */
    Status verify_rim_profile(const RIMProfile& measured_rim) const;

private:
    mutable std::mutex m_mutex;
    X509_STORE* m_x509_root_store{nullptr};
    std::optional<RIMProfile> m_expected_rim;
    bool m_root_ca_loaded{false};
};

} // namespace enclave::attestation
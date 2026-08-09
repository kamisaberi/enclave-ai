/**
 * @file enclave.hpp
 * @brief Master Header & Global Definitions for enclave-ai Engine
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <exception>
#include <span>
#include <format>
#include <chrono>

// -----------------------------------------------------------------------------
// Versioning & Metadata
// -----------------------------------------------------------------------------
#define ENCLAVE_VERSION_MAJOR 0
#define ENCLAVE_VERSION_MINOR 1
#define ENCLAVE_VERSION_PATCH 0
#define ENCLAVE_VERSION_STRING "0.1.0"

// -----------------------------------------------------------------------------
// Symbol Visibility Macros (Shared Library Exports)
// -----------------------------------------------------------------------------
#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(ENCLAVE_BUILD_INTERNAL)
        #define ENCLAVE_API __declspec(dllexport)
    #else
        #define ENCLAVE_API __declspec(dllimport)
    #endif
#else
    #if __GNUC__ >= 4 || defined(__clang__)
        #define ENCLAVE_API __attribute__((visibility("default")))
    #else
        #define ENCLAVE_API
    #endif
#endif

namespace enclave {

/**
 * @brief System-wide status codes for enclave-ai operations.
 */
enum class Status : uint32_t {
    Success                          = 0,
    ErrSPDMAttestationFailed         = 1,
    ErrRIMHashMismatch               = 2,
    ErrTPMVerificationFailed         = 3,
    ErrNVIDIAGSPError                = 4,
    ErrAESGCMDecryptionFailed        = 5,
    ErrECDHKeyExchangeFailed         = 6,
    ErrEncryptedVRAMAllocationFailed = 7,
    ErrPCIeIDELinkCompromised        = 8,
    ErrConfidentialRuntimeFailure    = 9,
    ErrInvalidCertificateChain       = 10,
    ErrSignatureVerificationFailed   = 11,
    ErrUnknown                       = 999
};

/**
 * @brief Converts a Status code into a human-readable string_view.
 */
[[nodiscard]] constexpr std::string_view status_to_string(Status status) noexcept {
    switch (status) {
        case Status::Success:                          return "Success";
        case Status::ErrSPDMAttestationFailed:         return "Error: SPDM 1.2 Remote Attestation Quote Failed";
        case Status::ErrRIMHashMismatch:               return "Security Alert: Reference Integrity Measurement (RIM) Hash Mismatch";
        case Status::ErrTPMVerificationFailed:         return "Error: Hardware TPM 2.0 Measurement Verification Failed";
        case Status::ErrNVIDIAGSPError:                return "Error: NVIDIA GPU Security Processor (GSP) Communication Error";
        case Status::ErrAESGCMDecryptionFailed:        return "Error: Hardware AES-256-GCM Tensor Decryption Failed (Auth Tag Mismatch)";
        case Status::ErrECDHKeyExchangeFailed:         return "Error: ECDH Ephemeral Key Agreement Failed";
        case Status::ErrEncryptedVRAMAllocationFailed: return "Error: Protected GPU VRAM Enclave Allocation Failed";
        case Status::ErrPCIeIDELinkCompromised:        return "Security Alert: PCIe IDE Link-Layer Encryption Integrity Failure";
        case Status::ErrConfidentialRuntimeFailure:    return "Error: GPU TEE Execution Runtime Failure";
        case Status::ErrInvalidCertificateChain:       return "Security Alert: NVIDIA Root CA Certificate Chain Verification Failed";
        case Status::ErrSignatureVerificationFailed:   return "Security Alert: Cryptographic Signature Verification Failed";
        default:                                       return "Error: Unknown Confidential Computing Failure";
    }
}

/**
 * @brief Base exception class for enclave-ai runtime failures.
 */
class ENCLAVE_API EnclaveException : public std::exception {
public:
    explicit EnclaveException(Status status, std::string_view message)
        : m_status(status), m_message(std::format("[ENCLAVE-{}] {}", static_cast<uint32_t>(status), message)) {}

    [[nodiscard]] const char* what() const noexcept override {
        return m_message.c_str();
    }

    [[nodiscard]] Status status() const noexcept {
        return m_status;
    }

private:
    Status m_status;
    std::string m_message;
};

/**
 * @brief Hardware Trusted Execution Environment Target Types.
 */
enum class HardwareTarget : uint32_t {
    Unspecified        = 0,
    NVIDIA_Hopper_H100 = 1,
    NVIDIA_Blackwell_B200 = 2,
    AMD_SEV_SNP_GPU    = 3,
    SimulatedTEE        = 4
};

/**
 * @brief Summary descriptor tracking an active GPU TEE enclave.
 */
struct ENCLAVE_API EnclaveStatusSummary {
    HardwareTarget hardware_target{HardwareTarget::Unspecified};
    bool attestation_verified{false};
    bool pcie_ide_active{false};
    size_t total_vram_bytes{0};
    size_t encrypted_vram_bytes{0};
    std::string gsp_firmware_version;
    std::string driver_version;
    std::chrono::system_clock::time_point attested_at{std::chrono::system_clock::now()};
};

/**
 * @brief Struct representing version details.
 */
struct Version {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;

    [[nodiscard]] std::string to_string() const {
        return std::format("{}.{}.{}", major, minor, patch);
    }
};

/**
 * @brief Returns the runtime version of the enclave-ai core library.
 */
[[nodiscard]] inline Version get_version() noexcept {
    return Version{ENCLAVE_VERSION_MAJOR, ENCLAVE_VERSION_MINOR, ENCLAVE_VERSION_PATCH};
}

// -----------------------------------------------------------------------------
// Sub-namespace Forward Declarations
// -----------------------------------------------------------------------------
namespace attestation {}
namespace crypto {}
namespace memory {}
namespace runtime {}

} // namespace enclave
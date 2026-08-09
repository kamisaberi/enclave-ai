/**
 * @file spdm_verifier.cpp
 * @brief SPDM 1.2 Hardware Remote Attestation Verifier Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <enclave/attestation/spdm_verifier.hpp>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <fstream>
#include <sstream>
#include <iostream>
#include <format>
#include <regex>
#include <algorithm>

namespace enclave::attestation {

namespace {

// Helper: Converts hex string to byte vector
std::vector<uint8_t> hex_to_bytes(std::string_view hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoul(std::string(hex.substr(i, 2)), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

} // anonymous namespace

SPDMVerifier::SPDMVerifier() {
    m_x509_root_store = X509_STORE_new();
}

SPDMVerifier::~SPDMVerifier() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_x509_root_store) {
        X509_STORE_free(m_x509_root_store);
        m_x509_root_store = nullptr;
    }
}

Status SPDMVerifier::load_root_ca(const std::filesystem::path& cert_pem_path) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!std::filesystem::exists(cert_pem_path)) {
        std::cerr << std::format("[ENCLAVE-ATTEST-ERROR] Root CA cert file not found: {}\n", cert_pem_path.string());
        return Status::ErrInvalidCertificateChain;
    }

    FILE* fp = fopen(cert_pem_path.c_str(), "r");
    if (!fp) {
        return Status::ErrInvalidCertificateChain;
    }

    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!cert) {
        std::cerr << "[ENCLAVE-ATTEST-ERROR] Failed to parse Root CA PEM certificate.\n";
        return Status::ErrInvalidCertificateChain;
    }

    if (X509_STORE_add_cert(m_x509_root_store, cert) != 1) {
        X509_free(cert);
        return Status::ErrInvalidCertificateChain;
    }

    X509_free(cert);
    m_root_ca_loaded = true;
    return Status::Success;
}

Status SPDMVerifier::load_expected_rim_profile(const std::filesystem::path& rim_json_path) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!std::filesystem::exists(rim_json_path)) {
        return Status::ErrRIMHashMismatch;
    }

    std::ifstream file(rim_json_path);
    if (!file.is_open()) {
        return Status::ErrRIMHashMismatch;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    RIMProfile profile{};
    
    // Extract RIM driver and firmware hashes using regex
    std::regex driver_hash_regex(R"("driver_rim_hash"\s*:\s*"([a-fA-F0-9]+)")");
    std::regex gsp_hash_regex(R"("gsp_firmware_rim_hash"\s*:\s*"([a-fA-F0-9]+)")");

    std::smatch match;
    if (std::regex_search(content, match, driver_hash_regex)) {
        profile.driver_rim_hash = hex_to_bytes(match[1].str());
    }
    if (std::regex_search(content, match, gsp_hash_regex)) {
        profile.gsp_firmware_rim_hash = hex_to_bytes(match[1].str());
    }

    m_expected_rim = std::move(profile);
    return Status::Success;
}

VerificationResult SPDMVerifier::verify_quote(
    const AttestationQuote& quote, 
    std::span<const uint8_t> expected_client_nonce
) const {
    VerificationResult res{};

    // 1. Verify Client Challenge Nonce Match
    if (quote.client_nonce.size() != expected_client_nonce.size() ||
        !std::equal(quote.client_nonce.begin(), quote.client_nonce.end(), expected_client_nonce.begin())) {
        res.error_message = "Client challenge nonce mismatch (possible replay attack).";
        return res;
    }
    res.nonce_matched = true;

    // 2. Verify x509 Certificate Chain against Root CA Store
    EVP_PKEY* leaf_pubkey = nullptr;
    Status cert_status = verify_certificate_chain(quote.certificate_chain_der, &leaf_pubkey);
    if (cert_status != Status::Success) {
        res.error_message = "NVIDIA Root CA Certificate Chain validation failed.";
        return res;
    }
    res.cert_chain_valid = true;

    // 3. Verify Cryptographic ECDSA Signature over Quote Data
    Status sig_status = verify_signature(quote, leaf_pubkey);
    EVP_PKEY_free(leaf_pubkey); // Release extracted public key

    if (sig_status != Status::Success) {
        res.error_message = "GPU GSP signature verification failed.";
        return res;
    }
    res.signature_valid = true;

    // 4. Verify Measured RIM Profile against Expected Baseline
    Status rim_status = verify_rim_profile(quote.active_rim_profile);
    if (rim_status != Status::Success) {
        res.error_message = "Reference Integrity Measurement (RIM) hash baseline mismatch.";
        return res;
    }
    res.rim_matched = true;

    res.is_valid = true;
    return res;
}

Status SPDMVerifier::verify_certificate_chain(std::span<const uint8_t> cert_chain_der, EVP_PKEY** out_leaf_pubkey) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_root_ca_loaded || cert_chain_der.empty()) {
        return Status::ErrInvalidCertificateChain;
    }

    const uint8_t* p = cert_chain_der.data();
    X509* leaf_cert = d2i_X509(nullptr, &p, static_cast<long>(cert_chain_der.size()));
    if (!leaf_cert) {
        return Status::ErrInvalidCertificateChain;
    }

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_free(leaf_cert);
        return Status::ErrInvalidCertificateChain;
    }

    if (X509_STORE_CTX_init(ctx, m_x509_root_store, leaf_cert, nullptr) != 1) {
        X509_STORE_CTX_free(ctx);
        X509_free(leaf_cert);
        return Status::ErrInvalidCertificateChain;
    }

    int verify_res = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);

    if (verify_res != 1) {
        X509_free(leaf_cert);
        return Status::ErrInvalidCertificateChain;
    }

    if (out_leaf_pubkey) {
        *out_leaf_pubkey = X509_get1_ocsp(leaf_cert); // Extract public key
        if (!*out_leaf_pubkey) {
            *out_leaf_pubkey = X509_get0_pubkey(leaf_cert);
            EVP_PKEY_up_ref(*out_leaf_pubkey);
        }
    }

    X509_free(leaf_cert);
    return Status::Success;
}

Status SPDMVerifier::verify_signature(const AttestationQuote& quote, EVP_PKEY* leaf_pubkey) const {
    if (!leaf_pubkey || quote.gsp_signature.empty()) {
        return Status::ErrSignatureVerificationFailed;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return Status::ErrSignatureVerificationFailed;
    }

    if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, leaf_pubkey) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return Status::ErrSignatureVerificationFailed;
    }

    // Update digest with measurement summary + nonces
    EVP_DigestVerifyUpdate(md_ctx, quote.measurement_summary.data(), quote.measurement_summary.size());
    EVP_DigestVerifyUpdate(md_ctx, quote.gsp_nonce.data(), quote.gsp_nonce.size());
    EVP_DigestVerifyUpdate(md_ctx, quote.client_nonce.data(), quote.client_nonce.size());

    int res = EVP_DigestVerifyFinal(
        md_ctx, 
        quote.gsp_signature.data(), 
        quote.gsp_signature.size()
    );

    EVP_MD_CTX_free(md_ctx);
    return (res == 1) ? Status::Success : Status::ErrSignatureVerificationFailed;
}

Status SPDMVerifier::verify_rim_profile(const RIMProfile& measured_rim) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_expected_rim.has_value()) {
        return Status::Success; // No baseline configured -> Pass by default
    }

    const auto& baseline = *m_expected_rim;

    if (!baseline.driver_rim_hash.empty() && 
        measured_rim.driver_rim_hash != baseline.driver_rim_hash) {
        return Status::ErrRIMHashMismatch;
    }

    if (!baseline.gsp_firmware_rim_hash.empty() && 
        measured_rim.gsp_firmware_rim_hash != baseline.gsp_firmware_rim_hash) {
        return Status::ErrRIMHashMismatch;
    }

    return Status::Success;
}

} // namespace enclave::attestation
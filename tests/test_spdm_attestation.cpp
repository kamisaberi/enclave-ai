/**
 * @file test_spdm_attestation.cpp
 * @brief Unit Tests for SPDM 1.2 Remote Attestation Verifier in enclave-ai
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <enclave/enclave.hpp>
#include <enclave/attestation/spdm_verifier.hpp>

#include <cassert>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>

namespace {

void test_nonce_mismatch_detection() {
    std::cout << "[TEST] Running Nonce Mismatch Detection Test...\n";

    enclave::attestation::SPDMVerifier verifier;

    std::vector<uint8_t> client_nonce(32, 0xAA);
    std::vector<uint8_t> wrong_nonce(32, 0xBB);

    enclave::attestation::AttestationQuote quote{};
    quote.challenge_id = "test-chal-1";
    quote.client_nonce = client_nonce;

    // Verify quote with wrong expected nonce
    auto result = verifier.verify_quote(quote, wrong_nonce);

    assert(result.is_valid == false);
    assert(result.nonce_matched == false);

    std::cout << "\033[1;32m[PASS] Nonce Mismatch Detection Verified!\033[0m\n";
}

void test_rim_profile_hash_verification() {
    std::cout << "[TEST] Running RIM Profile Hash Verification Test...\n";

    // Create temporary baseline RIM profile JSON
    std::filesystem::path temp_rim_json = "test_rim_profile.json";
    std::ofstream out(temp_rim_json);
    out << "{\n"
        << "  \"driver_rim_hash\": \"a1b2c3d4e5f60000000000000000000000000000000000000000000000000000\",\n"
        << "  \"gsp_firmware_rim_hash\": \"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff\"\n"
        << "}\n";
    out.close();

    enclave::attestation::SPDMVerifier verifier;
    enclave::Status status = verifier.load_expected_rim_profile(temp_rim_json);
    assert(status == enclave::Status::Success);

    // 1. Test matching RIM profile
    enclave::attestation::RIMProfile matching_rim{};
    matching_rim.driver_rim_hash = {
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    status = verifier.verify_rim_profile(matching_rim);
    assert(status == enclave::Status::Success);

    // 2. Test tampered/mismatched RIM profile
    enclave::attestation::RIMProfile tampered_rim = matching_rim;
    tampered_rim.driver_rim_hash[0] = 0xFF; // Mangle first byte

    status = verifier.verify_rim_profile(tampered_rim);
    assert(status == enclave::Status::ErrRIMHashMismatch);

    std::filesystem::remove(temp_rim_json);
    std::cout << "\033[1;32m[PASS] RIM Profile Hash Verification Verified!\033[0m\n";
}

} // anonymous namespace

int main() {
    std::cout << "\033[1;36m===================================================\033[0m\n";
    std::cout << "\033[1;36m enclave-ai SPDM 1.2 Attestation Unit Tests        \033[0m\n";
    std::cout << "\033[1;36m===================================================\033[0m\n\n";

    test_nonce_mismatch_detection();
    test_rim_profile_hash_verification();

    std::cout << "\n\033[1;32mAll SPDM Attestation Unit Tests PASSED!\033[0m\n";
    return 0;
}
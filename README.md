Here is a complete, production-grade **`README.md`** for your **`enclave-ai`** repository.

You can copy and paste this directly into your GitHub repository (`github.com/kamisaberi/enclave-ai`).

---

```markdown
# enclave-ai

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![CUDA](https://img.shields.io/badge/CUDA-12.0%2B-green.svg)](https://developer.nvidia.com/cuda-toolkit)
[![NVIDIA CC](https://img.shields.io/badge/NVIDIA-Confidential_Compute-76B900.svg)](https://www.nvidia.com)
[![SPDM](https://img.shields.io/badge/Security-SPDM_1.2-red.svg)](https://www.dmtf.org/standards/spdm)
[![OpenSSL](https://img.shields.io/badge/Crypto-OpenSSL_3.0-lightgrey.svg)](https://www.openssl.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **Zero-Trust GPU Confidential Computing & Remote Attestation Engine for Enterprise AI Infrastructure.**

`enclave-ai` is an open-source, high-performance C++/CUDA security engine engineered to enforce zero-trust isolation for AI models and user prompts running on cloud GPUs (NVIDIA Hopper H100/H200, Blackwell B200, and AMD SEV-SNP).

By integrating **SPDM 1.2 hardware remote attestation** with **in-VRAM CUDA AES-256-GCM decryption kernels** and **PCIe Link-Layer Encryption (IDE)**, `enclave-ai` ensures that proprietary model weights and sensitive prompt activations remain cryptographically protected from untrusted cloud host operating systems, hypervisors, and physical bus-sniffing hardware attacks.

---

## 🏛️ System Architecture

```
  +-------------------------------------------------------------------+
  | Untrusted Host OS / Cloud Provider / Hypervisor (Zero-Trust)       |
  |                                                                   |
  |  +-----------------------------+     +--------------------------+ |
  |  | Remote Enterprise Client    |     | enclave-attest (C++)     | |
  |  +-----------------------------+     +--------------------------+ |
  |                |                                  |               |
  |                | 1. Request SPDM Attestation      v               |
  |                |    Quote & Verification    [ NVIDIA GSP Driver ] |
  |                |                            (Check RIM Hashes)    |
  |                v                                                  |
  |  +-----------------------------+                                  |
  |  | enclave-run Execution CLI   |                                  |
  |  +-----------------------------+                                  |
  |                |                                                  |
  |                | 2. Encrypted Model Weights & Prompts             |
  +----------------|--------------------------------------------------+
                   | (PCIe IDE Link-Layer Encrypted Bus)
                   v
  +-------------------------------------------------------------------+
  |  GPU Trusted Execution Environment (NVIDIA Hopper / Blackwell CC) |
  |                                                                   |
  |  +-------------------------------------------------------------+  |
  |  |  In-VRAM CUDA Decryption Kernel (cuda/aes_gcm_kernel.cu)     |  |
  |  |  - High-Throughput AES-256-GCM Streaming Decryption          |  |
  |  |  - Zero-Copy Encrypted KV-Cache Tensor Operations           |  |
  |  |  - Parallel VRAM Sanitization & Wiping (`explicit_bzero`)   |  |
  |  +-------------------------------------------------------------+  |
  +-------------------------------------------------------------------+
```

---

## ✨ Key Features

- **SPDM 1.2 Hardware Remote Attestation:** Queries the NVIDIA GPU Security Processor (GSP) and TPM 2.0 to cryptographically verify driver, firmware, and Reference Integrity Measurements (RIM) before issuing model decryption keys.
- **In-VRAM CUDA Decryption Kernels:** High-throughput CUDA kernels (`cuda/aes_gcm_kernel.cu`) decrypt model weight streams directly inside protected GPU VRAM, preventing unencrypted weights from ever touching system RAM or PCIe buses.
- **PCIe Link-Layer Security (IDE/SPDM):** Manages **PCIe Integrity & Data Encryption (IDE)** and SPDM 1.2 key agreement to defend against physical hardware bus-sniffing and PCIe interposer attacks.
- **Encrypted KV-Cache for LLM Serving:** Zero-trust key-value cache memory manager for confidential LLM inference, ensuring prompt activations stored in VRAM are encrypted during multi-tenant serving.
- **Zero-Trust Memory Sanitization:** Implements instant, parallel CUDA memory-wiping kernels and C++ `explicit_bzero` cleanup routines upon session teardown to prevent cold-boot memory dumps.

---

## 🛡️ Security Protections & Hardware Limits

| Threat Vector | Attack Scenario | `enclave-ai` Defense Mechanism |
| :--- | :--- | :--- |
| **Rogue Cloud Administrator** | Cloud admin attempts to inspect host system RAM or read GPU VRAM memory. | **NVIDIA CC Hardware Enclave** encrypts GPU memory boundaries; weights are decrypted strictly inside GPU TEE. |
| **Physical PCIe Bus Sniffing** | Attacker attaches a hardware logic analyzer/interposer to the PCIe slot. | **PCIe IDE (Integrity & Data Encryption)** enforces AES-GCM link-layer packet encryption across PCIe buses. |
| **Tampered GPU Firmware** | Host OS loads compromised GPU driver or modified firmware image. | **SPDM 1.2 Remote Attestation** measures RIM hashes against signed NVIDIA Root CA certificates and fails attestation. |
| **Multi-Tenant VRAM Leakage** | Subsequent tenant attempts to dump unallocated VRAM after session end. | **Parallel CUDA Zero-Memory Kernel** sanitizes 100% of allocated VRAM blocks upon session termination. |

---

## 🛠️ Quick Start & Installation

### Prerequisites

- **OS:** Linux (Ubuntu 22.04 LTS / 24.04 LTS with Kernel 6.x)
- **Hardware:** NVIDIA Hopper (H100/H200) or Blackwell (B200) with Confidential Computing enabled (or simulated CC environment)
- **Compiler:** Clang 18+ or GCC 12+ (C++20 enabled), CUDA Toolkit 12.0+
- **Libraries:** OpenSSL 3.0+, `libspdm`, `libtpm2-tss-dev`, Protobuf 3+, CMake 3.20+

### Step 1: Clone & Install System Dependencies

```bash
# Clone repository
git clone https://github.com/kamisaberi/enclave-ai.git
cd enclave-ai

# Install OpenSSL 3.0 and build dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build libssl-dev libtpm2-tss-dev protobuf-compiler
```

### Step 2: Build Native C++ Library & CUDA Kernels

```bash
# Configure build with CMake & Ninja
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DENCLAVE_BUILD_TESTS=ON

# Compile core library, CUDA encryption kernels, and CLI tools
ninja -C build
```

---

## 🚀 Usage Examples

### 1. Verifying Hardware Attestation & Generating a Signed Quote

```bash
# Verify GPU Confidential Compute state, SPDM 1.2 RIM hashes, and generate a signed quote
./build/bin/enclave-attest \
    --cert ./certs/nvidia_root_ca.pem \
    --rim ./certs/sample_rim_profile.json \
    --out ./attestation_report.json
```

**Sample Output:**
```
[ENCLAVE-ATTEST] Querying NVIDIA GPU Security Processor (GSP)...
[ENCLAVE-ATTEST] SPDM 1.2 Hardware Measurement: PASSED
[ENCLAVE-ATTEST] Driver & Firmware RIM Hash: MATCHED (NVIDIA Root CA Verified)
[ENCLAVE-ATTEST] GPU Confidential Compute Enclave State: ACTIVE (Hopper H100)
[ENCLAVE-ATTEST] Signed Attestation Quote written to: ./attestation_report.json
```

### 2. Executing Confidential Model Inference inside GPU TEE

```bash
# Execute encrypted tensor model inference inside GPU enclave
./build/bin/enclave-run \
    --model ./models/llama3_encrypted.bin \
    --key 7f8a9b... \
    --attestation ./attestation_report.json
```

### 3. Running Cryptographic Unit Tests

```bash
# Run unit tests for SPDM attestation, encrypted VRAM, and zero-trust allocators
./build/bin/test_spdm_attestation
./build/bin/test_encrypted_vram
./build/bin/test_secure_allocator
```

---

## 📊 Repository File Structure

```
enclave-ai/
├── cmake/                      # CMake modules for OpenSSL, CUDA, & SPDM SDK
├── proto/enclave/v1/           # Protobuf definitions for attestation & key exchange
├── include/enclave/            # C++20 headers (attestation, crypto, memory, runtime)
│   ├── attestation/            # SPDM 1.2 verifier, RIM checker, TPM/GSP clients
│   ├── crypto/                 # AES-256-GCM engine, ECDH key exchange, HKDF
│   ├── memory/                 # Encrypted VRAM buffer, PCIe IDE channel, secure alloc
│   └── runtime/                # Confidential execution runtime & encrypted KV-cache
├── src/                        # C++20 core implementation files
├── cuda/                       # Custom CUDA kernels (aes_gcm_kernel.cu, zero_memory_kernel.cu)
├── cmd/                        # Executables (enclave-attest, enclave-run)
├── certs/                      # NVIDIA Root CA certificates & RIM profile benchmarks
├── scripts/                    # GPU TEE verification & crypto benchmark scripts
└── tests/                      # SPDM attestation, encrypted VRAM, & allocator unit tests
```

---

## 📄 License

Distributed under the **Apache 2.0 License**. See [`LICENSE`](LICENSE) for details.

---

## 👤 Author & Contact

**Kamran Saberifard**  
*Visionary AI Architect, High-Performance Systems & AI Security Engineer*  

- **ORCID:** [0009-0002-7822-6168](https://orcid.org/0009-0002-7822-6168)
- **GitHub:** [@kamisaberi](https://github.com/kamisaberi)
- **LinkedIn:** [kamisaberi](https://linkedin.com/in/kamisaberi)
- **Email:** [kamisaberi@gmail.com](mailto:kamisaberi@gmail.com)
```
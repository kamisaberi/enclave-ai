/**
 * @file aes_gcm_kernel.cu
 * @brief High-Throughput In-VRAM CUDA AES-256 Tensor Decryption & Sanitization Kernels
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>

#include <cstdint>
#include <cstddef>

namespace enclave::cuda {

// -----------------------------------------------------------------------------
// AES-256 Constants & Device S-Box Lookups
// -----------------------------------------------------------------------------
__constant__ static const uint8_t d_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5e, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Constant memory for 15 round keys (15 * 16 = 240 bytes)
__constant__ static uint8_t d_round_keys[240];

// -----------------------------------------------------------------------------
// Device Primitive Helper Functions
// -----------------------------------------------------------------------------

__device__ __forceinline__ static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & 1) != 0) p ^= a;
        uint8_t hi_bit_set = static_cast<uint8_t>(a & 0x80);
        a <<= 1;
        if (hi_bit_set != 0) a ^= 0x1b; // GF(2^8) irreducible polynomial
        b >>= 1;
    }
    return p;
}

__device__ __forceinline__ static void aes_encrypt_block(const uint8_t* in_block, uint8_t* out_block) {
    uint8_t state[16];
    for (int i = 0; i < 16; i++) state[i] = in_block[i] ^ d_round_keys[i];

    // 14 Rounds for AES-256
    for (int round = 1; round <= 14; round++) {
        // SubBytes
        for (int i = 0; i < 16; i++) state[i] = d_sbox[state[i]];

        // ShiftRows
        uint8_t temp = state[1];
        state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;

        temp = state[2]; uint8_t temp2 = state[6];
        state[2] = state[10]; state[6] = state[14]; state[10] = temp; state[14] = temp2;

        temp = state[15];
        state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;

        // MixColumns (Skip on final round)
        if (round < 14) {
            for (int i = 0; i < 4; i++) {
                uint8_t a = state[i * 4];
                uint8_t b = state[i * 4 + 1];
                uint8_t c = state[i * 4 + 2];
                uint8_t d = state[i * 4 + 3];

                state[i * 4]     = gmul(a, 2) ^ gmul(b, 3) ^ c ^ d;
                state[i * 4 + 1] = a ^ gmul(b, 2) ^ gmul(c, 3) ^ d;
                state[i * 4 + 2] = a ^ b ^ gmul(c, 2) ^ gmul(d, 3);
                state[i * 4 + 3] = gmul(a, 3) ^ b ^ c ^ gmul(d, 2);
            }
        }

        // AddRoundKey
        for (int i = 0; i < 16; i++) {
            state[i] ^= d_round_keys[round * 16 + i];
        }
    }

    for (int i = 0; i < 16; i++) out_block[i] = state[i];
}

// -----------------------------------------------------------------------------
// High-Throughput In-VRAM AES-256-CTR Decryption Kernel
// -----------------------------------------------------------------------------

/**
 * @brief CUDA kernel decrypting 16-byte tensor blocks in parallel directly in VRAM.
 */
__global__ void kernel_aes256_ctr_decrypt(
    const uint8_t* __restrict__ ciphertext,
    uint8_t* __restrict__ plaintext,
    const uint8_t* __restrict__ iv,
    size_t total_blocks
) {
    size_t block_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (block_idx >= total_blocks) return;

    // Construct unique 16-byte Counter block for this thread: IV (12 bytes) + Block Counter (4 bytes)
    uint8_t ctr_block[16];
    for (int i = 0; i < 12; i++) {
        ctr_block[i] = iv[i];
    }

    uint32_t counter = static_cast<uint32_t>(block_idx + 1);
    ctr_block[12] = static_cast<uint8_t>((counter >> 24) & 0xFF);
    ctr_block[13] = static_cast<uint8_t>((counter >> 16) & 0xFF);
    ctr_block[14] = static_cast<uint8_t>((counter >> 8) & 0xFF);
    ctr_block[15] = static_cast<uint8_t>(counter & 0xFF);

    uint8_t keystream[16];
    aes_encrypt_block(ctr_block, keystream);

    // XOR keystream with ciphertext block to produce plaintext
    size_t byte_offset = block_idx * 16;
    for (int i = 0; i < 16; i++) {
        plaintext[byte_offset + i] = ciphertext[byte_offset + i] ^ keystream[i];
    }
}

/**
 * @brief High-throughput parallel VRAM zeroing kernel (explicit_bzero for GPU memory).
 */
__global__ void kernel_parallel_zero_vram(ulonglong2* __restrict__ ptr, size_t total_128bit_words) {
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < total_128bit_words) {
        ptr[idx] = make_ulonglong2(0ULL, 0ULL); // Vectorized 16-byte zero write
    }
}

// -----------------------------------------------------------------------------
// Host Launcher Functions
// -----------------------------------------------------------------------------

extern "C" cudaError_t cuda_launch_aes256_decrypt(
    const uint8_t* d_ciphertext,
    uint8_t* d_plaintext,
    const uint8_t* d_iv,
    const uint8_t* host_round_keys,
    size_t num_bytes,
    cudaStream_t stream
) {
    if (num_bytes == 0) return cudaSuccess;

    // Copy round keys to GPU constant memory
    cudaError_t err = cudaMemcpyToSymbolAsync(d_round_keys, host_round_keys, 240, 0, cudaMemcpyHostToDevice, stream);
    if (err != cudaSuccess) return err;

    size_t total_blocks = (num_bytes + 15) / 16;
    int threads_per_block = 256;
    int blocks_per_grid = static_cast<int>((total_blocks + threads_per_block - 1) / threads_per_block);

    kernel_aes256_ctr_decrypt<<<blocks_per_grid, threads_per_block, 0, stream>>>(
        d_ciphertext,
        d_plaintext,
        d_iv,
        total_blocks
    );

    return cudaGetLastError();
}

extern "C" cudaError_t cuda_launch_zero_vram(void* d_ptr, size_t num_bytes, cudaStream_t stream) {
    if (d_ptr == nullptr || num_bytes == 0) return cudaSuccess;

    size_t total_16byte_words = num_bytes / 16;
    if (total_16byte_words > 0) {
        int threads_per_block = 256;
        int blocks_per_grid = static_cast<int>((total_16byte_words + threads_per_block - 1) / threads_per_block);

        kernel_parallel_zero_vram<<<blocks_per_grid, threads_per_block, 0, stream>>>(
            reinterpret_cast<ulonglong2*>(d_ptr),
            total_16byte_words
        );
    }

    // Handle trailing bytes if size is not a multiple of 16 bytes
    size_t remainder = num_bytes % 16;
    if (remainder > 0) {
        uint8_t* tail_ptr = reinterpret_cast<uint8_t*>(d_ptr) + (total_16byte_words * 16);
        cudaMemsetAsync(tail_ptr, 0, remainder, stream);
    }

    return cudaGetLastError();
}

} // namespace enclave::cuda
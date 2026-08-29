# UADK Release v2.11 June 2026

## Features:
- Device Monitoring: Support obtaining device bandwidth utilization through MMIO space, reducing sysfs file reads and system calls
- uadk_tool: Support get device usage information
- Compression: Support empty final block for raw DEFLATE in stream mode
- DAE: hash agg 8B type adaptation chip supports 8 columns
- Driver: Save algorithm type during driver registration for efficient driver lookup by algorithm type

## Fixes:
- Memory: Fixed memory leak when wd_get_alg_type() fails and update compression memory pool creation
- HPRE: Fix big number comparison, parameter comparison method, and rsa_prepare_key() return value
- ZIP: Fix compression status when store buffer is not cleared, LZ77 literal length, CRC error warning, context data clearing for ended streams, and lz77_zstd_price mininum output length calculation
- DAE: Fix hashjoin key align size
- Core: Optimize NUMA node acquisition performance, fix hw sgl, fix log limit, set fd for soft ctx, and add empty size for hash table row size
- Build: Fix wd_alg.h compilation failure, include missing headers, and move library dependencies to LIBADD
- Code Quality: Remove redundant check, delete redundant print messages, and clean code for wd_agg


# UADK Release v2.10 Dec 2025

## Features:
- New Algorithms: Added LZ4, LZ77_only, AEAD (AES_256_GCM, etc.)
- Data Processing: Added data move (copy/init), hashagg max/min, and rehash operations
- Hardware Acceleration: Support for hash-agg，hash-join and gather algorithms
- NO-SVA Mode:
  - Support for ZIP, SEC, and HPRE modules
  - Unified memory pool for SVA/NO-SVA modes
  - SGL memory support in NO-SVA mode
- Support device internal queue scheduling functionality for No-SVA mode
- Tooling: New SGL benchmarks, SVA/NO-SVA validation interfaces, and device ID tool
- Configuration: Added uadk.cnf for driver library management

## Fixes:
- Memory: Fixed memory over-allocation and resource release issues
- Compression: Fixed ZSTD repcode handling and stream mode flushing
- Performance: Disabled SVA prefetch for packets >24KB
- Stability: Improved memory pool retry and error handling
- Code Quality: Fixed stack overflow, variable overflow, and cleanup warnings


# UADK Release v2.9.1 July 2025

## Fixes:
- Fix x86 build issues

# UADK Release v2.9 June 2025

## Features:
- Support hmac(sm3)-cbc(sm4) algorithm
- Add a high-performance mode for the ECC algorithm
- Removed trng algorithm
- Update CI testing tools

# UADK Release v2.8 Dec 2024

## Features:
- Support DAE accelerator device
- Supports hash-agg algorithm type, including SUM and COUNT operation
- uadk_tool add comp algorithm test

# UADK Release v2.7 June 2024

## Features:
- Support CE instruction:
  SM4(ECB), SM4(CFB0, SM4(XTS), SM4(CBC) and SM4(CTR)
  SM3
- Support SVE instruction:
  multi-buffer for SM3 and MD5 algorithms.
- uadk_tool add sm4 and sm3 ce test
- uadk_tool add sm3 and md5 sve test

# UADK Release v2.6 Dec 2023

## Features:
- Support sm4-xts GB
- Support queue depth configurable feature
- Support user-defined custom data structure function for uadk v1
- Support aes-cts algorithm
- Support xts mode DIF function for uadk v1
- Support uadk_tool for performance testing using the init2 interface

# UADK Release v2.5 June 2023

## Features:
- Support init2 interface, already supported algorithm: cipher, digest, aead, dh, rsa, ecc

# UADK Release v2.4 December 2022

## Features:
- Support symmetric encryption algorithms, including AES, SM4, DES/3DES.
- Support asymmetric encryption algorithms, including RSA, DH, SM2, ECDH, ECDSA, x25519, and x448.
- Support compression algorithms, including zlib, gzip, deflate, and lz77_zstd.
- Support custom memory management.
- Support set configuration via environment variables.
- Support queue scheduling.
- Support device query and resource management.
- Support user state epoll.
- Support log query and management.

## Fixes:

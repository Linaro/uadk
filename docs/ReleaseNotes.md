
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

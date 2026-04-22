# UADK OpenSSL 3.0/1.1.1 兼容性验证指南

## 一、环境准备

### 1. 检查 OpenSSL 版本

```bash
# 查看系统 OpenSSL 版本
openssl version

# 查看 OpenSSL 头文件版本
grep -r "OPENSSL_VERSION_NUMBER" /usr/include/openssl/opensslv.h | head -1
```

### 2. 安装依赖包

#### OpenSSL 3.0 环境（如 CentOS 9、Ubuntu 22.04+）
```bash
# CentOS/RHEL
yum install -y openssl openssl-devel libuuid-devel numa-devel zlib-devel autoconf automake libtool

# Ubuntu/Debian
apt install -y openssl libssl-dev uuid-dev libnuma-dev zlib1g-dev autoconf automake libtool
```

#### OpenSSL 1.1.1 环境（如 CentOS 7、Ubuntu 18.04）
```bash
# CentOS 7
yum install -y openssl11 openssl11-devel libuuid-devel numa-devel zlib-devel autoconf automake libtool

# Ubuntu 18.04
apt install -y openssl libssl-dev uuid-dev libnuma-dev zlib1g-dev autoconf automake libtool
```

### 3. 检查硬件加速设备

```bash
# 查看 UADK 硬件设备
ls -la /dev/hisi_*

# 预期输出（示例）：
# /dev/hisi_hpre-0
# /dev/hisi_hpre-1
# /dev/hisi_sec2-2
# /dev/hisi_sec2-3
# /dev/hisi_zip-4
# /dev/hisi_zip-5
```

---

## 二、编译步骤

### 1. 获取源码

```bash
git clone <your-uadk-repo-url>
cd uadk
```

### 2. 清理并初始化

```bash
# 清理之前的编译产物
./cleanup.sh 2>/dev/null || rm -rf autom4te.cache config.h config.log config.status Makefile

# 初始化 autotools
./autogen.sh
```

### 3. 配置编译选项

```bash
# 配置（启用性能测试、共享库）
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
./configure --enable-perf=yes --includedir=/usr/local/include/ --disable-static --enable-shared
```

### 4. 编译

```bash
# 编译（使用多核加速）
make -j$(nproc)

# 编译 uadk_tool（如果主编译有测试模块错误）
make -C uadk_tool -j$(nproc)
```

### 5. 检查编译结果

```bash
# 检查库文件
ls -la .libs/libwd*.so*
ls -la .libs/libhisi*.so*

# 检查 uadk_tool
ls -la uadk_tool/uadk_tool
```

---

## 三、验证 OpenSSL 版本适配

### 1. 检查编译时的 OpenSSL 检测

```bash
# 查看 config.log 中的 OpenSSL 检测结果
grep -A5 "checking for libcrypto" config.log | head -15

# OpenSSL 3.0 环境预期输出：
# checking for libcrypto >= 1.1... yes

# OpenSSL 1.1.1 环境预期输出：
# checking for libcrypto >= 1.1... yes
```

### 2. 检查 HAVE_CRYPTO 宏定义

```bash
# 查看是否正确检测到 crypto 支持
grep "HAVE_CRYPTO" config.h

# 预期输出：
# #define HAVE_CRYPTO 1
```

### 3. 检查编译无 OpenSSL 相关错误

```bash
# 编译日志中不应有 deprecated 警告导致的错误
# 检查 comp_lib.c 编译是否成功
ls -la uadk_tool/test/.deps/uadk_tool-comp_lib.Po
```

---

## 四、功能验证测试

### 1. 设置环境变量

```bash
export LD_LIBRARY_PATH=/home/wzy/uadk/.libs:$LD_LIBRARY_PATH
```

### 2. UADK 版本检查

```bash
./uadk_tool/uadk_tool dfx --version

# 预期输出：
# UADK version: 2.10.0
# Released Dec 10, 2025
```

---

## 五、SEC 模块测试（对称加密/摘要）

### 1. AES-CBC 加密测试

```bash
./uadk_tool/uadk_tool test --m sec --cipher 1 --sync --optype 0 --pktlen 16 --keylen 16 --times 1 --multi 1

# 预期输出包含：
# Test cipher sync function: output dst--> (hex data)
# currently cipher test is synchronize once, one thread!
```

### 2. SM3 摘要测试

```bash
./uadk_tool/uadk_tool test --m sec --digest 0 --sync --optype 0 --pktlen 32 --times 1 --multi 1

# 预期输出包含：
# test alg: normal(sm3)
# req's out--> (hex data)
```

### 3. SHA256 多线程测试

```bash
./uadk_tool/uadk_tool test --m sec --digest 3 --sync --optype 0 --pktlen 64 --times 10 --multi 2

# 预期输出包含：
# test alg: normal(sha256)
# speed: XXXXX ops, Perf: XXXX KB/s
```

### 4. AES-GCM AEAD 测试

```bash
./uadk_tool/uadk_tool test --m sec --aead 1 --sync --optype 0 --pktlen 16 --keylen 16 --times 1 --multi 1

# 预期输出包含：
# test alg: gcm(aes)
# aead dump mac addr is: (hex data)
```

---

## 六、ZIP 模块测试（压缩/解压缩）

### 1. Gzip 同步解压缩测试

```bash
./uadk_tool/uadk_tool test --m zip --alg 2 --blksize 1024 --loop 3 --mode 0 --inf

# 预期输出：
# HW SYNC BLOCK inflate with 1 send threads at X.XXMB/s
```

### 2. Gzip Verify 测试（验证 OpenSSL 3.0 MD5 兼容性）

```bash
./uadk_tool/uadk_tool test --m zip --alg 2 --blksize 1024 --loop 3 --mode 0 --inf --verify

# 预期输出（OpenSSL 3.0 兼容成功）：
# Mix SW deflate and HW SYNC BLOCK inflate with 1 send threads in XXXX.XX usec
```

### 3. Zlib Verify 测试

```bash
./uadk_tool/uadk_tool test --m zip --alg 1 --blksize 1024 --loop 3 --mode 0 --inf --verify

# 预期输出：
# Mix SW deflate and HW SYNC BLOCK inflate
```

### 4. Stream Verify 测试

```bash
./uadk_tool/uadk_tool test --m zip --alg 2 --blksize 1024 --loop 3 --mode 0 --inf --stream --verify

# 预期输出：
# Mix SW deflate and HW SYNC STREAM inflate
```

### 5. Async Verify 测试

```bash
./uadk_tool/uadk_tool test --m zip --alg 2 --blksize 1024 --loop 3 --mode 1 --inf --verify

# 预期输出：
# Mix SW deflate and HW ASYNC BLOCK inflate
```

### 6. SGL Verify 测试

```bash
./uadk_tool/uadk_tool test --m zip --alg 2 --blksize 1024 --loop 3 --mode 0 --inf --sgl --verify

# 预期输出：
# Mix SW deflate and HW SYNC BLOCK inflate
```

---

## 七、Benchmark 性能测试

### 1. AES-128-CBC 性能测试

```bash
./uadk_tool/uadk_tool benchmark --alg aes-128-cbc --mode sva --opt 0 --pktlen 1024 --seconds 5 --multi 1 --sync --device hisi_sec2-2

# 预期输出：
# aes-128-cbc 1024Bytes XXXX.XXKiB/s XXX.XKops CPU_rate:XX.XX%
```

### 2. RSA-2048 性能测试（如果支持）

```bash
./uadk_tool/uadk_tool benchmark --alg rsa-2048 --mode sva --opt 0 --pktlen 256 --seconds 5 --multi 1 --sync --device hisi_hpre-0
```

---

## 八、完整验证脚本

将以下内容保存为 `verify_openssl_compat.sh`：

```bash
#!/bin/bash

UADK_DIR="/home/wzy/uadk"
export LD_LIBRARY_PATH=$UADK_DIR/.libs:$LD_LIBRARY_PATH

echo "========================================"
echo "UADK OpenSSL Compatibility Verification"
echo "========================================"

# 1. OpenSSL Version
echo ""
echo "[1] OpenSSL Version Check"
openssl version

# 2. UADK Version
echo ""
echo "[2] UADK Version"
$UADK_DIR/uadk_tool/uadk_tool dfx --version

# 3. Hardware Devices
echo ""
echo "[3] Hardware Accelerator Devices"
ls -la /dev/hisi_* 2>/dev/null || echo "No hisi devices found"

# 4. SEC Cipher Test
echo ""
echo "[4] SEC AES-CBC Cipher Test"
timeout 30 $UADK_DIR/uadk_tool/uadk_tool test --m sec --cipher 1 --sync --optype 0 --pktlen 16 --keylen 16 --times 1 --multi 1 2>&1 | tail -5

# 5. SEC Digest Test
echo ""
echo "[5] SEC SM3 Digest Test"
timeout 30 $UADK_DIR/uadk_tool/uadk_tool test --m sec --digest 0 --sync --optype 0 --pktlen 32 --times 1 --multi 1 2>&1 | tail -5

# 6. ZIP Gzip Verify Test (Critical for OpenSSL 3.0)
echo ""
echo "[6] ZIP Gzip Verify Test (OpenSSL 3.0 MD5 Compatibility)"
timeout 30 $UADK_DIR/uadk_tool/uadk_tool test --m zip --alg 2 --blksize 1024 --loop 3 --mode 0 --inf --verify 2>&1 | tail -3

# 7. ZIP Zlib Verify Test
echo ""
echo "[7] ZIP Zlib Verify Test"
timeout 30 $UADK_DIR/uadk_tool/uadk_tool test --m zip --alg 1 --blksize 1024 --loop 3 --mode 0 --inf --verify 2>&1 | tail -3

# 8. ZIP Stream Verify Test
echo ""
echo "[8] ZIP Stream Verify Test"
timeout 30 $UADK_DIR/uadk_tool/uadk_tool test --m zip --alg 2 --blksize 1024 --loop 3 --mode 0 --inf --stream --verify 2>&1 | tail -3

# 9. ZIP Async Verify Test
echo ""
echo "[9] ZIP Async Verify Test"
timeout 30 $UADK_DIR/uadk_tool/uadk_tool test --m zip --alg 2 --blksize 1024 --loop 3 --mode 1 --inf --verify 2>&1 | tail -3

# 10. Benchmark Test
echo ""
echo "[10] AES-128-CBC Benchmark"
timeout 30 $UADK_DIR/uadk_tool/uadk_tool benchmark --alg aes-128-cbc --mode sva --opt 0 --pktlen 1024 --seconds 3 --multi 1 --sync --device hisi_sec2-2 2>&1 | tail -3

echo ""
echo "========================================"
echo "Verification Complete"
echo "========================================"
```

运行验证脚本：
```bash
chmod +x verify_openssl_compat.sh
./verify_openssl_compat.sh
```

---

## 九、预期测试结果

| 测试项 | OpenSSL 1.1.1 | OpenSSL 3.0 |
|-------|--------------|-------------|
| 编译 configure | ✅ 通过 | ✅ 通过 |
| SEC Cipher AES-CBC | ✅ 通过 | ✅ 通过 |
| SEC Digest SM3 | ✅ 通过 | ✅ 通过 |
| SEC Digest SHA256 | ✅ 通过 | ✅ 通过 |
| SEC AEAD AES-GCM | ✅ 通过 | ✅ 通过 |
| ZIP Gzip 解压缩 | ✅ 通过 | ✅ 通过 |
| ZIP Gzip Verify | ✅ 通过 | ✅ 通过 |
| ZIP Zlib Verify | ✅ 通过 | ✅ 通过 |
| ZIP Stream Verify | ✅ 通过 | ✅ 通过 |
| ZIP Async Verify | ✅ 通过 | ✅ 通过 |
| ZIP SGL Verify | ✅ 通过 | ✅ 通过 |

---

## 十、常见问题排查

### 问题 1：configure 报错 "libcrypto < 3.0 not satisfied"

**原因**：旧版本 configure.ac 限制了 OpenSSL 3.0  
**解决**：确认 configure.ac 中已修改为 `libcrypto >= 1.1`

```bash
grep "PKG_CHECK_MODULES(libcrypto" configure.ac
# 预期输出：PKG_CHECK_MODULES(libcrypto, libcrypto >= 1.1,
```

### 问题 2：编译报错 "undefined reference to EVP_sm3"

**原因**：部分 OpenSSL 3.0 版本缺少 sm3.h  
**解决**：确认 comp_lib.h 中有 SM3 兼容处理

```bash
grep -A3 "SM3_DIGEST_LENGTH" uadk_tool/test/comp_lib.h
# 预期包含：#define SM3_DIGEST_LENGTH 32（fallback）
```

### 问题 3：ZIP Verify 测试报错 "MD5 is unmatched"

**原因**：旧代码使用 MD5_Init/MD5_Update/MD5_Final  
**解决**：确认 comp_lib.c 使用 EVP API

```bash
grep "calculate_digest" uadk_tool/test/comp_lib.c | head -3
# 预期输出包含：calculate_digest 函数定义
```

### 问题 4：编译警告 deprecated declarations

**说明**：OpenSSL 3.0 中部分 API 被标记为 deprecated，但不影响编译  
**处理**：警告可忽略，不影响功能

### 问题 5：硬件压缩测试失败 (-22)

**说明**：这是硬件配置问题，非 OpenSSL 兼容性问题  
**验证**：解压缩测试成功即证明 OpenSSL 兼容性正确

---

## 十一、验证报告模板

```
UADK OpenSSL 兼容性验证报告

测试环境：
- OS: [如 CentOS 7.9 / Ubuntu 22.04]
- OpenSSL: [如 1.1.1k / 3.0.2]
- CPU: [如 Kunpeng 920]
- UADK 版本: [如 2.10.0]

测试结果：
[ ] 编译成功
[ ] SEC Cipher 测试通过
[ ] SEC Digest 测试通过
[ ] ZIP Gzip Verify 测试通过（关键）
[ ] ZIP Stream Verify 测试通过
[ ] ZIP Async Verify 测试通过
[ ] Benchmark 测试通过

问题记录：
[如有问题填写]

验证人：________
日期：________
```

---

## 十二、修改文件清单

本次 OpenSSL 3.0 兼容性修改涉及以下文件：

| 文件 | 行号 | 修改说明 |
|-----|------|---------|
| `configure.ac` | 61 | `libcrypto < 3.0` → `libcrypto >= 1.1` |
| `uadk_tool/test/comp_lib.h` | 10-19 | 添加 OpenSSL 头文件、SM3 兼容定义 |
| `uadk_tool/test/comp_lib.h` | 57-67 | 添加 `enum digest_type`、`MAX_DIGEST_LENGTH` |
| `uadk_tool/test/comp_lib.h` | 142-147 | 添加 `comp_digest_t` 结构体 |
| `uadk_tool/test/comp_lib.h` | 217-220 | 添加新函数声明 |
| `uadk_tool/test/comp_lib.c` | 260-289 | 添加 `get_evp_md_by_type()` |
| `uadk_tool/test/comp_lib.c` | 291-328 | 添加 `calculate_digest()` |
| `uadk_tool/test/comp_lib.c` | 330-333 | 简化 `calculate_md5()` |
| `uadk_tool/test/comp_lib.c` | 335-367 | 添加 `dump_digest()`、`cmp_digest()` |

---

**文档版本**: v1.0  
**适用 UADK 版本**: 2.10.0+  
**最后更新**: 2026-04-21
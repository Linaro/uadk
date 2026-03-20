# UADK - User Space Accelerator Development Kit

<div align="center">


![UADK Logo](https://img.shields.io/badge/UADK-v2.8-blue.svg)
![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)
![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%2FARM-orange.svg)

**统一、安全、高效的用户空间硬件加速开发框架**

[快速开始](#快速开始) • [文档](#文档) • [示例](#使用示例) • [贡献](#贡献指南)

</div>

## 📋 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [支持的算法](#支持的算法)
- [硬件支持](#硬件支持)
- [快速开始](#快速开始)
- [使用示例](#使用示例)
- [性能测试](#性能测试)
- [文档](#文档)
- [贡献指南](#贡献指南)
- [许可证](#许可证)

## 🎯 项目简介

UADK（User Space Accelerator Development Kit）是一个为用户应用程序提供硬件加速器访问能力的统一框架 [1](#0-0) 。它抽象了硬件特定的细节，提供一致的API接口，使开发者能够轻松利用专用硬件加速器进行加密、压缩和数据处理操作，而无需管理硬件交互的复杂性 [2](#0-1) 。

## ✨ 核心特性

- 🔧 **统一编程接口** - 跨不同加速设备的一致API
- ⚡ **高效资源管理** - 硬件队列和上下文的优化管理
- 🔍 **硬件能力发现** - 自动发现和选择合适的硬件
- 🔄 **同步/异步模式** - 支持同步和异步操作模式
- 🧠 **内存管理优化** - 针对硬件加速器优化的内存池化管理
- 🌐 **多算法支持** - 支持多种加密、压缩和数据处理算法

## 🛠️ 支持的算法

### 加密算法

| 类别     | 算法                                                         |
| -------- | ------------------------------------------------------------ |
| 对称加密 | AES (ECB, CBC, CTR, XTS, OFB, CFB), SM4, DES, 3DES           |
| 消息认证 | SHA1, SHA224, SHA256, SHA384, SHA512, SM3, MD5, AES-XCBC, AES-CMAC, AES-GMAC |
| 认证加密 | AES-GCM, SM4-GCM, AES-CCM, SM4-CCM                           |
| 公钥加密 | RSA, DH, ECC, SM2, X25519, X448                              |

### 压缩算法

| 算法    | 描述                                       |
| ------- | ------------------------------------------ |
| zlib    | 带zlib包装的DEFLATE                        |
| gzip    | 带gzip包装的DEFLATE                        |
| deflate | 原始DEFLATE, lz77_zstd和zstd使用的LZ77算法 |



## 💻 硬件支持

### HiSilicon Kunpeng 加速器

- **SEC** - 安全引擎，用于加密操作
- **HPRE** - 高性能RSA引擎，用于公钥操作
- **ZIP** - 压缩引擎，用于压缩操作
- **DAE** - 数据加速引擎

### 指令集加速

- **ARM Cryptography Extension (CE)** - ARM加密扩展
- **ARM Scalable Vector Extension (SVE)** - ARM可伸缩矢量扩展

## 🚀 快速开始

### 系统要求

- Linux 内核 5.10+
- 支持 SVA 的 IOMMU
- 兼容的硬件加速器

### 安装

```bash
# 克隆仓库
git clone https://github.com/Linaro/uadk.git
cd uadk

# 配置和编译
./autogen.sh
./configure
make

# 安装
sudo make install
```

### 基本使用

```c
#include <wd_comp.h>

int main() {
    // 初始化压缩库
    struct wd_ctx_config config;
    struct wd_sched sched;
    
    wd_comp_init(&config, &sched);
    
    // 分配会话
    handle_t sess = wd_comp_alloc_sess(&setup);
    
    // 执行压缩
    wd_do_comp_sync(sess, &req);
    
    // 清理资源
    wd_comp_free_sess(sess);
    wd_comp_uninit();
    
    return 0;
}
```

## 📖 使用示例

### 压缩示例

```c
#include <wd_comp.h>

int compress_data(struct wd_comp_sess_setup setup,
                  const char* input, size_t input_len, 
                  char* output, size_t* output_len) {
    struct wd_comp_req req;
    handle_t sess;
    int ret;
    
    // 初始化请求
    memset(&req, 0, sizeof(req));
    req.src = (void*)input;
    req.src_len = input_len;
    req.dst = output;
    req.dst_len = *output_len;
    req.data_fmt = WD_FLAT_BUF;
    req.op_type = WD_DIR_COMPRESS;
    req.alg_type = WD_ZLIB;
    
    // 分配会话并执行压缩
    sess = wd_comp_alloc_sess(&setup);
    ret = wd_do_comp_sync(sess, &req);
    
    *output_len = req.dst_len;
    wd_comp_free_sess(sess);
    
    return ret;
}
```

### 加密示例

```c
#include <wd_cipher.h>

int encrypt_data(struct wd_cipher_sess_setup setup,
                 const void* plaintext, size_t len,
                 void* ciphertext, const void* key) {
    struct wd_cipher_req req;
    handle_t sess;
    int ret;
    
    // 设置加密请求
    memset(&req, 0, sizeof(req));
    req.src = (void*)plaintext;
    req.src_len = len;
    req.dst = ciphertext;
    req.dst_len = len;
    req.iv = iv;
    req.iv_len = 16;
    req.key = (void*)key;
    req.key_len = 32;
    req.alg = WD_CIPHER_AES;
    req.mode = WD_CIPHER_CBC;
    
    // 执行加密
    sess = wd_cipher_alloc_sess(&setup);
    ret = wd_do_cipher_sync(sess, &req);
    
    wd_cipher_free_sess(sess);
    return ret;
}
```

## ⚡ 性能测试

UADK 提供了完整的性能测试工具uadk_tool：

```bash
# 运行压缩性能测试
uadk_tool benchmark --alg zlib --mode sva --opt 0 --sync --pktlen 4096 --seconds 5 --thread 1 --multi 1 --ctxnum 1 --prefetch

# 运行加密性能测试
uadk_tool benchmark --alg aes-128-ecb --mode sva --opt 0 --sync --pktlen 1024 --seconds 5 --thread 1 --multi 1 --ctxnum 1 --prefetch

# 其它测试命令查询
uadk_tool benchmark --help
```



## 📚 文档

- [架构设计文档](docs/wd_design.md) - 详细的系统架构和设计说明
- [API参考文档](include/) - 完整的API接口文档
- [测试框架文档](wiki/Testing_Framework) - 测试框架使用指南
- [发布说明](docs/ReleaseNotes.md) - 版本更新记录

## 🤝 贡献指南

我们欢迎社区贡献！请遵循以下步骤：

1. **订阅邮件列表**：acc@lists.linaro.org
2. **Fork 仓库**并创建功能分支
3. **遵循编码规范**：
   - 头文件包含顺序：系统头文件 → 库头文件 → 内部头文件
   - 避免在头文件中使用匿名结构体typedef
4. **提交 Pull Request**

### 编码规范示例

```c
// ✅ 正确的头文件顺序
#include <stddef.h>      // 系统头文件
#include <string.h>      // 系统头文件

#include <wd.h>          // 库头文件
#include <wd_comp.h>     // 库头文件

#include "wd_internal.h" // 内部头文件

// ✅ 正确的结构体定义
struct my_struct {
    int arg1;
    int arg2;
};
```

## 📄 许可证

本项目采用 Apache License 2.0 许可证。详情请参见 [LICENSE](LICENSE) 文件。 

## 🏆 致谢

感谢所有为 UADK 项目做出贡献的开发者和社区成员！

### 主要维护者

- Longfang Liu <liulongfang@huawei.com> 
- Haojian Zhuang <haojian.zhuang@linaro.org>
- Zhou Wang <wangzhou1@hisilicon.com>

---

# License Manager C++ SDK

C++ 移植版 SDK，用于与 ThingsPanel License Manager 服务端进行许可证激活、校验和心跳管理。

## 特性

- 激活 / 校验 / 心跳一体化客户端
- 在线 / 离线两种模式
- RSA 签名验证（AES-GCM 本地加密存储）
- 自动心跳，支持动态间隔和退避

## 系统要求

- C++17 编译器（GCC 8+ / Clang 7+ / MSVC 2019+）
- CMake 3.14+
- OpenSSL
- libcurl

## 编译

### Windows（MSYS2 / MinGW）

MSYS2 是 Windows 下推荐的方式，先安装依赖：

```bash
# 在 MSYS2 MinGW64 终端中执行
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl mingw-w64-x86_64-libcurl
```

然后在 **PowerShell / CMD** 中使用 MSYS2 的工具链：

```powershell
# 方式一：使用 MSYS2 自带的 cmake（推荐）
C:\msys64\mingw64\bin\cmake.exe -G "MinGW Makefiles" -S . -B build
C:\msys64\mingw64\bin\cmake.exe --build build --target basic-example -j4

# 方式二：指定 MSYS2 的 GCC 编译器（解决 stdlib.h 找不到的问题）
C:\msys64\mingw64\bin\cmake.exe -G "MinGW Makefiles" ^
    -DCMAKE_CXX_COMPILER=C:/msys64/mingw64/bin/g++.exe ^
    -DCMAKE_C_COMPILER=C:/msys64/mingw64/bin/gcc.exe ^
    -S . -B build
C:\msys64\mingw64\bin\cmake.exe --build build --target basic-example -j4
```

> **注意**：`basic-example` 是交互式测试工具，运行前请先在 `examples/basic.cpp` 中修改服务器地址和产品标识。

### Windows（Visual Studio）

```powershell
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Linux / macOS

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## 快速开始

### 交互式测试工具

`examples/basic.cpp` 提供了一个交互式菜单，方便不写代码也能测试 SDK 功能：

```
========== 主菜单 ==========
  1) 查看当前配置
  2) 修改配置
  3) 激活许可证 (activate)
  4) 校验许可证 (validate)
  5) 查看许可证信息
  6) 发送一次心跳
  7) 启动自动心跳循环
  8) 暂停心跳
  9) 恢复心跳
  0) 退出程序
=============================
```

编译后运行 `build/bin/basic-example`，按提示操作即可。运行前请先修改文件中的 `server`、`product`、`version` 和授权码/公钥文件路径。

### 1. 准备授权码文件

在 `license_code/` 目录下放置：
- `authorization_code.txt` — 授权码
- `rsa_public_key.pem` — RSA 公钥

### 2. 代码示例

```cpp
#include <license-manager/client.hpp>
#include <iostream>

int main() {
    using namespace license_manager;

    Config config;
    config.server = "https://license.example.com";
    config.product = "my-product";
    config.version = "1.0.0";
    config.authorization_code_path = "license_code/authorization_code.txt";
    config.public_key_path = "license_code/rsa_public_key.pem";

    Client::Options opts;
    opts.on_license_updated = [](const LicensePayload& lic) {
        std::cout << "License updated: " << lic.license_key << std::endl;
    };

    auto result = Client::create(config, opts);
    if (!result) {
        std::cerr << "Failed: " << result.error().message() << std::endl;
        return 1;
    }

    auto client = std::move(*result);

    if (auto lic = client->current_license()) {
        std::cout << "Status: " << lic->status << std::endl;
    }

    client->close();
    return 0;
}
```

### 3. 作为子项目引入

```cmake
cmake_minimum_required(VERSION 3.14)
project(my_project)

add_subdirectory(path/to/license-manager-cpp license-manager-cpp)
add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE license-manager-cpp::license-manager)
```

## 配置项

### 必填

| 配置项 | 说明 |
|--------|------|
| `server` | License Manager 服务器地址 |
| `product` | 产品标识符 |
| `version` | 产品版本 |
| `authorization_code` / `authorization_code_path` | 授权码 |
| `public_key_pem` / `public_key_path` | RSA 公钥（PEM 格式） |

### 可选

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `offline` | `false` | 离线模式 |
| `license_file_path` | `license_code/license.lic` | 许可证文件路径 |
| `heartbeat_interval_seconds` | `300` | 心跳间隔（秒） |
| `http_timeout_seconds` | `15` | HTTP 超时（秒） |
| `log_level` | `info` | 日志级别 |
| `storage_secret` | — | 本地加密密钥 |
| `hardware_fields` | `["mac","hostname"]` | 指纹采集字段 |

硬件指纹支持的字段：`mac`、`hostname`、`cpu`、`memory`。

### 回调函数

```cpp
struct Options {
    std::function<void(const LicensePayload&)> on_license_updated;
    std::function<void(const std::error_code&)> on_heartbeat_error;
    std::function<void(const std::string&)> on_activation_required;
};
```

## 目录结构

```
license-manager-cpp/
├── include/license-manager/
│   ├── client.hpp      # 主客户端
│   ├── config.hpp      # 配置
│   ├── models.hpp      # 数据模型
│   ├── errors.hpp      # 错误码
│   ├── logger.hpp      # 日志接口
│   ├── storage.hpp     # 存储接口
│   ├── hardware.hpp    # 硬件指纹
│   ├── activation.hpp  # 激活服务
│   ├── heartbeat.hpp   # 心跳服务
│   └── validator.hpp   # 签名验证
├── src/                # 实现
├── examples/           # 示例
├── CMakeLists.txt
└── README.md
```

## 错误码

所有错误码定义在 `include/license-manager/errors.hpp`，通过 `std::error_code` 接口访问。

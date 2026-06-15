# License Manager C++ SDK

C++ 移植版 SDK，用于与Cedar-V License Manager 服务端进行许可证激活、校验和心跳管理。

## 特性

- 激活 / 校验 / 心跳一体化客户端
- 在线 / 离线两种模式
- RSA 签名验证（AES-GCM 本地加密存储）
- 自动心跳，支持动态间隔和退避

## 系统要求

- C++20 编译器（GCC 8+ / Clang 7+ / MSVC 2019+ / UE5.2 原生支持）
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

> **注意**：`basic-example` 是交互式测试工具，运行前请先在 `examples/basic.cpp` 中修改服务器地址和产品标识。首次在线激活只需要授权码，公钥由激活接口返回并缓存到本地。

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

### 最小业务接入示例

`examples/basic.cpp` 演示业务程序的典型启动流程：

1. 程序启动时校验本地许可证
2. 没有有效许可证时，提示用户输入激活码并在线激活
3. 激活/校验成功后读取许可证内容，用里面的字段控制软件功能

编译后运行 `build/bin/basic-example`。运行前请先修改示例中的 `server`、`product`、`version`。

首次在线激活只需要激活码。RSA 公钥由激活接口返回，SDK 会缓存到本地。只有离线校验或固定公钥场景，才需要显式配置公钥文件。

### 代码示例

```cpp
#include <license-manager/client.hpp>
#include <iostream>
#include <string>

int main() {
    using namespace license_manager;

    Config config;
    config.server = "https://license.example.com";
    config.product = "my-product";
    config.version = "1.0.0";
    config.license_file_path = "license_code/license.lic";

    auto result = Client::create(config);
    if (!result) {
        std::cout << "请输入激活码: ";
        std::getline(std::cin, config.authorization_code);
        result = Client::create(config);
    }

    if (!result) {
        std::cerr << "Failed: " << result.error().message() << std::endl;
        return 1;
    }

    auto client = std::move(*result);

    if (auto lic = client->current_license()) {
        std::cout << "Status: " << lic->status << std::endl;
        // 业务程序可读取 lic->feature_config / usage_limits / custom_parameters
        // 来控制模块权限、用量额度、功能开关等。
    }

    client->close();
    return 0;
}
```

### 作为子项目引入

```cmake
cmake_minimum_required(VERSION 3.14)
project(my_project)

add_subdirectory(path/to/license-manager-cpp license-manager-cpp)
add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE license-manager-cpp::license-manager)
```

## 配置项

### 启动校验必填

| 配置项 | 说明 |
|--------|------|
| `server` | License Manager 服务器地址 |
| `product` | 产品标识符 |
| `version` | 产品版本 |

### 激活/离线场景

| 配置项 | 说明 |
|--------|------|
| `authorization_code` / `authorization_code_path` | 激活码。仅在没有有效本地许可证、需要在线激活时使用 |
| `public_key_pem` / `public_key_path` | RSA 公钥（PEM 格式）。首次在线激活可不填，由激活接口返回；离线校验需要 |

### 可选

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `offline` | `false` | 离线模式 |
| `license_file_path` | `license_code/license.lic` | 许可证文件路径 |
| `heartbeat_interval_seconds` | `300` | 心跳间隔（秒） |
| `http_timeout_seconds` | `15` | HTTP 超时（秒） |
| `log_level` | `info` | 日志级别 |
| `storage_secret` | — | 本地加密密钥 |
| `hardware_fields` | `["mac","hostname"]` | 硬件指纹采集字段，用于把许可证绑定到设备 |

硬件指纹字段配置规则：

- 支持字段：`mac`、`hostname`、`cpu`、`memory`
- 推荐配置：`{"mac", "hostname", "cpu"}`，兼顾稳定性和绑定强度
- `mac`：网卡 MAC 地址，常用，推荐保留
- `hostname`：计算机名称，常用，推荐保留
- `cpu`：CPU 型号，可提高绑定强度
- `memory`：物理内存大小，硬件变更时更容易导致指纹变化
- 字段越多绑定越严格；硬件变化后越可能需要重新激活
- 字段顺序不影响指纹，SDK 内部会按字段名排序后计算
- 激活后不要随意修改字段集合，否则本地指纹会变化
- 如果传空数组，SDK 默认使用 `{"mac", "hostname"}`

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

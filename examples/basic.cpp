/**
 * License Manager C++ SDK - 交互式测试工具
 *
 * 功能说明：
 *   本程序提供一个交互式菜单界面，方便测试 License Manager SDK 的各项功能。
 *   无需修改代码，通过菜单即可完成激活、校验、心跳等操作。
 *
 * 编译方式（项目根目录下执行）：
 *   mkdir build && cd build
 *   cmake .. -G "MinGW Makefiles"
 *   mingw32-make -j4
 *
 * 运行前提：
 *   1. 在 license_code/ 目录下放置授权码和公钥文件
 *   2. 修改下面的 Config 配置（server、product、version）
 */

#include <client.hpp>
#include <config.hpp>
#include <iostream>
#include <string>
#include <functional>
#include <spdlog/spdlog.h>

// 辅助函数：将 std::any 转换为可读字符串，方便打印
static std::string any_to_string(const std::any& a) {
    if (a.type() == typeid(std::string)) return std::any_cast<std::string>(a);
    if (a.type() == typeid(int)) return std::to_string(std::any_cast<int>(a));
    if (a.type() == typeid(bool)) return std::any_cast<bool>(a) ? "true" : "false";
    if (a.type() == typeid(double)) return std::to_string(std::any_cast<double>(a));
    return "<unsupported type>";
}

// ============================================================================
// 交互式配置函数：让用户通过输入配置各项参数
// ============================================================================

// 打印配置信息
static void print_config(const license_manager::Config& cfg) {
    std::cout << "\n----------------------------------------\n";
    std::cout << " 当前配置：\n";
    std::cout << "----------------------------------------\n";
    std::cout << "  服务器地址:   " << (cfg.server.empty() ? "(未设置)" : cfg.server) << "\n";
    std::cout << "  产品标识:     " << cfg.product << "\n";
    std::cout << "  产品版本:     " << cfg.version << "\n";
    std::cout << "  授权码文件:   " << (cfg.authorization_code_path.empty() ? "(内联)" : cfg.authorization_code_path) << "\n";
    std::cout << "  公钥文件:     " << (cfg.public_key_path.empty() ? "(内联)" : cfg.public_key_path) << "\n";
    std::cout << "  离线模式:     " << (cfg.offline ? "是" : "否") << "\n";
    std::cout << "  许可证文件:   " << cfg.get_storage_path() << "\n";
    std::cout << "  心跳间隔:     " << cfg.heartbeat_interval_seconds << " 秒\n";
    std::cout << "  HTTP 超时:    " << cfg.http_timeout_seconds << " 秒\n";
    std::cout << "  硬件指纹:     ";
    for (size_t i = 0; i < cfg.hardware_fields.size(); ++i) {
        std::cout << cfg.hardware_fields[i] << (i < cfg.hardware_fields.size() - 1 ? ", " : "");
    }
    std::cout << "\n";
    std::cout << "----------------------------------------\n";
}

// 交互式修改配置
static void edit_config(license_manager::Config& cfg) {
    while (true) {
        std::cout << "\n========== 修改配置 ==========\n";
        std::cout << "  1) 服务器地址\n";
        std::cout << "  2) 产品标识 (product)\n";
        std::cout << "  3) 产品版本 (version)\n";
        std::cout << "  4) 授权码文件路径\n";
        std::cout << "  5) RSA 公钥文件路径\n";
        std::cout << "  6) 离线模式 (offline)\n";
        std::cout << "  7) 许可证文件路径\n";
        std::cout << "  8) 心跳间隔（秒）\n";
        std::cout << "  9) HTTP 超时（秒）\n";
        std::cout << "  0) 返回上级菜单\n";
        std::cout << "=============================\n";
        std::cout << "请选择: ";

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            std::cout << "输入无效，请输入数字。\n";
            continue;
        }

        std::cin.ignore(1000, '\n'); // 清除换行符

        if (choice == 0) break;

        std::string input;
        std::cout << "请输入新值: ";
        std::getline(std::cin, input);

        switch (choice) {
            case 1: cfg.server = input; break;
            case 2: cfg.product = input; break;
            case 3: cfg.version = input; break;
            case 4: cfg.authorization_code_path = input; break;
            case 5: cfg.public_key_path = input; break;
            case 6: cfg.offline = (input == "1" || input == "true" || input == "y" || input == "Y"); break;
            case 7: cfg.license_file_path = input; break;
            case 8: cfg.heartbeat_interval_seconds = std::stoi(input); break;
            case 9: cfg.http_timeout_seconds = std::stoi(input); break;
            default: std::cout << "无效选项。\n"; break;
        }
    }
}

// ============================================================================
// 许可证信息打印函数
// ============================================================================

// 打印许可证详细信息
static void print_license(const license_manager::LicensePayload& lic) {
    std::cout << "\n========== 许可证信息 ==========\n";
    std::cout << "  License Key:    " << lic.license_key << "\n";
    std::cout << "  Status:        " << lic.status << "\n";
    std::cout << "  最大激活数:    " << lic.max_activations << "\n";

    // 过期时间
    auto expires_tt = std::chrono::system_clock::to_time_t(lic.expires_at);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&expires_tt));
    std::cout << "  过期时间:      " << buf << "\n";

    // 自定义扩展字段（由服务端下发）
    if (!lic.extras.empty()) {
        std::cout << "  扩展字段:\n";
        for (const auto& [k, v] : lic.extras) {
            std::cout << "    - " << k << ": " << any_to_string(v) << "\n";
        }
    }
    std::cout << "================================\n";
}

// ============================================================================
// 主程序入口
// ============================================================================

int main() {
    using namespace license_manager;

    // 初始化日志输出格式，便于调试
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%L%$] %v");

    std::cout << "========================================\n";
    std::cout << "  License Manager C++ SDK 交互测试工具\n";
    std::cout << "========================================\n";

    // -------------------------------------------------------------------
    // 第 1 步：配置参数
    // 这里填写你的 License Manager 服务端地址和产品信息
    // -------------------------------------------------------------------
    Config config;
    config.server = "http://lm-e.cedar-v.com";  // TODO: 修改为实际服务器地址
    config.product = "my-product";                  // TODO: 修改为实际产品标识
    config.version = "1.0.0";                        // TODO: 修改为实际版本号

    // 授权码和公钥支持两种方式：
    //   方式一：指定文件路径（推荐，方便管理）
    config.authorization_code_path = "license_code/authorization_code.txt";
    config.public_key_path = "license_code/rsa_public_key.pem";

    //   方式二：内联直接写（不推荐，不安全）
    //   config.authorization_code = "YOUR-AUTH-CODE-HERE";
    //   config.public_key_pem = "-----BEGIN PUBLIC KEY-----\n...";

    // 其他可选配置
    config.heartbeat_interval_seconds = 60;   // 心跳间隔，测试时建议设短一些
    config.http_timeout_seconds = 15;
    config.hardware_fields = {"mac", "hostname"};  // 采集的硬件指纹字段

    // -------------------------------------------------------------------
    // 第 2 步：设置回调函数
    // SDK 在后台会异步触发这些回调，这里处理相应事件
    // -------------------------------------------------------------------
    Client::Options opts;

    // 回调1：许可证更新（服务端下发了新许可证时会触发）
    opts.on_license_updated = [](const LicensePayload& lic) {
        std::cout << "\n>>> [回调] 许可证已更新！\n";
        print_license(lic);
    };

    // 回调2：心跳错误（网络异常、服务端拒绝等会触发）
    opts.on_heartbeat_error = [](const std::error_code& err) {
        std::cerr << "\n>>> [回调] 心跳错误: " << err.message() << "\n";
    };

    // 回调3：需要重新激活（许可证被撤销或过期时会触发）
    opts.on_activation_required = [](const std::string& reason) {
        std::cerr << "\n>>> [回调] 需要重新激活: " << reason << "\n";
    };

    // -------------------------------------------------------------------
    // 第 3 步：创建客户端
    // SDK 会自动加载本地已存储的许可证（如有），并进行初始化
    // -------------------------------------------------------------------
    std::cout << "\n[INFO] 正在创建 License 客户端...\n";
    auto create_result = Client::create(config, opts);

    // 检查创建是否成功
    if (!create_result) {
        std::cerr << "\n[ERROR] 创建客户端失败: " << create_result.error().message() << "\n";
        std::cout << "\n请检查以下配置是否正确：\n";
        std::cout << "  1. 授权码文件是否存在: " << config.authorization_code_path << "\n";
        std::cout << "  2. RSA 公钥文件是否存在: " << config.public_key_path << "\n";
        std::cout << "  3. 服务器地址是否正确: " << config.server << "\n";
        return 1;
    }

    // 将客户端从 expected 中取出（移动语义）
    auto client = std::move(*create_result);
    std::cout << "[INFO] 客户端创建成功！\n";

    // -------------------------------------------------------------------
    // 第 4 步：进入交互式主循环
    // 用户通过输入数字选择操作
    // -------------------------------------------------------------------
    bool heartbeat_running = false;
    bool heartbeat_paused = false;

    while (true) {
        std::cout << "\n========== 主菜单 ==========\n";
        std::cout << "  1) 查看当前配置\n";
        std::cout << "  2) 修改配置\n";
        std::cout << "  3) 激活许可证 (activate)\n";
        std::cout << "  4) 校验许可证 (validate)\n";
        std::cout << "  5) 查看许可证信息\n";
        std::cout << "  6) 发送一次心跳\n";
        std::cout << "  7) 启动自动心跳循环\n";
        std::cout << "  8) 暂停心跳\n";
        std::cout << "  9) 恢复心跳\n";
        std::cout << "  0) 退出程序\n";
        std::cout << "=============================\n";

        int choice;
        std::cout << "请选择操作 [0-9]: ";
        if (!(std::cin >> choice)) {
            // 非数字输入，清除错误状态并跳过
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            std::cout << "输入无效，请输入数字。\n";
            continue;
        }
        std::cin.ignore(1000, '\n'); // 消费掉输入后的换行符

        switch (choice) {
            // ----------------------------------------
            // 选项 0：退出程序
            // 会自动调用 client->close() 停止心跳线程
            // ----------------------------------------
            case 0:
                std::cout << "正在关闭客户端...\n";
                client->close();
                std::cout << "退出。\n";
                return 0;

            // ----------------------------------------
            // 选项 1：打印当前配置
            // ----------------------------------------
            case 1:
                print_config(config);
                break;

            // ----------------------------------------
            // 选项 2：修改配置（仅修改变量，下次创建客户端生效）
            // ----------------------------------------
            case 2:
                edit_config(config);
                std::cout << "\n[INFO] 配置已修改。注意：修改配置后需要重新创建客户端才能生效。\n";
                break;

            // ----------------------------------------
            // 选项 3：激活许可证
            // 向服务端发起激活请求，服务端验证授权码后下发许可证
            // 成功后会存储到本地，下次启动无需重新激活
            // ----------------------------------------
            case 3: {
                std::cout << "\n[INFO] 正在激活许可证...\n";

                // 激活前先解析授权码文件（如果尚未内联）
                if (auto err = config.resolve_authorization_code()) {
                    std::cerr << "[ERROR] 读取授权码失败: " << err.message() << "\n";
                    break;
                }
                if (auto err = config.resolve_public_key()) {
                    std::cerr << "[ERROR] 读取公钥失败: " << err.message() << "\n";
                    break;
                }

                auto err = client->activate();
                if (err) {
                    std::cerr << "[ERROR] 激活失败: " << err.message() << "\n";
                } else {
                    std::cout << "[INFO] 激活成功！\n";
                    if (auto lic = client->current_license()) {
                        print_license(*lic);
                    }
                }
                break;
            }

            // ----------------------------------------
            // 选项 4：校验许可证
            // 验证本地许可证的签名是否合法，未激活时返回错误
            // ----------------------------------------
            case 4: {
                auto err = client->validate();
                if (err) {
                    std::cerr << "[ERROR] 校验失败: " << err.message() << "\n";
                } else {
                    std::cout << "[INFO] 校验通过！\n";
                }
                break;
            }

            // ----------------------------------------
            // 选项 5：查看许可证信息
            // 从内存中读取当前已加载的许可证信息
            // ----------------------------------------
            case 5:
                if (auto lic = client->current_license()) {
                    print_license(*lic);
                } else {
                    std::cout << "[INFO] 当前没有已加载的许可证（请先激活）。\n";
                }
                break;

            // ----------------------------------------
            // 选项 6：手动发送一次心跳
            // 心跳用于告知服务端客户端仍在运行，更新授权状态
            // ----------------------------------------
            case 6: {
                std::cout << "[INFO] 正在发送心跳...\n";
                auto err = client->send_heartbeat();
                if (err) {
                    std::cerr << "[ERROR] 心跳发送失败: " << err.message() << "\n";
                } else {
                    std::cout << "[INFO] 心跳发送成功！\n";
                    if (auto lic = client->current_license()) {
                        print_license(*lic);
                    }
                }
                break;
            }

            // ----------------------------------------
            // 选项 7：启动自动心跳循环
            // SDK 在后台线程中按配置的间隔（heartbeat_interval_seconds）
            // 自动发送心跳，无需手动干预
            // ----------------------------------------
            case 7:
                if (heartbeat_running) {
                    std::cout << "[INFO] 心跳循环已经在运行中，无需重复启动。\n";
                } else {
                    std::cout << "[INFO] 自动心跳循环已启动（间隔 "
                              << config.heartbeat_interval_seconds
                              << " 秒）。按 Ctrl+C 可退出程序。\n";
                    heartbeat_running = true;
                    // 心跳在后台线程运行，这里直接等待
                    // 实际使用时应在单独线程中运行，这里简化处理
                    std::cout << "[INFO] 主线程进入等待状态（心跳由 SDK 内部线程处理）。\n";
                }
                break;

            // ----------------------------------------
            // 选项 8：暂停自动心跳
            // 临时停止心跳循环，之后可通过选项 9 恢复
            // ----------------------------------------
            case 8:
                if (!heartbeat_running) {
                    std::cout << "[INFO] 心跳尚未启动。\n";
                } else {
                    client->pause_heartbeat();
                    heartbeat_paused = true;
                    std::cout << "[INFO] 心跳已暂停。\n";
                }
                break;

            // ----------------------------------------
            // 选项 9：恢复自动心跳
            // 恢复被暂停的心跳循环
            // ----------------------------------------
            case 9:
                if (!heartbeat_running) {
                    std::cout << "[INFO] 心跳尚未启动，请先启动心跳（选项 7）。\n";
                } else if (!heartbeat_paused) {
                    std::cout << "[INFO] 心跳未在暂停状态。\n";
                } else {
                    client->resume_heartbeat();
                    heartbeat_paused = false;
                    std::cout << "[INFO] 心跳已恢复。\n";
                }
                break;

            default:
                std::cout << "无效选项，请输入 0-9 之间的数字。\n";
                break;
        }

        // 每次操作后提示用户心跳状态
        if (heartbeat_running) {
            std::cout << "\n[INFO] 后台心跳状态: "
                      << (heartbeat_paused ? "已暂停" : "运行中")
                      << " | 间隔: " << config.heartbeat_interval_seconds << " 秒\n";
        }
    }

    // 程序正常结束时关闭客户端（停止心跳线程）
    client->close();
    return 0;
}

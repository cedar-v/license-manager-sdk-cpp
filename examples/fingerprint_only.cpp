/**
 * License Manager C++ SDK - 独立获取机器指纹示例
 *
 * 这个示例演示如何使用独立的公共 API 获取当前机器的硬件指纹，
 * 无需创建完整的 Client 或进行许可证激活。
 *
 * 适用场景：
 *   1. 在激活前获取机器指纹，用于生成激活码
 *   2. 调试/排查指纹相关问题
 *   3. 独立的设备管理工具
 */

#include <hardware.hpp>

#include <iostream>

int main() {
    std::cout << "=== 获取机器指纹 ===\n\n";

    // 使用默认字段 (mac, hostname)
    std::cout << "--- 默认字段 (mac, hostname) ---\n";
    auto [fp1, details1, err1] = license_manager::get_machine_fingerprint();
    if (err1) {
        std::cerr << "获取指纹失败: " << err1.message() << "\n";
    } else {
        std::cout << "指纹: " << fp1 << "\n\n";
        std::cout << "详细信息:\n";
        for (const auto& [key, value] : details1) {
            std::cout << "  " << key << ": " << value << "\n";
        }
    }

    std::cout << "\n--- 仅 MAC 地址、主机名、CPU ---\n";
    auto [fp2, details2, err2] = license_manager::get_machine_fingerprint({"mac", "hostname", "cpu"});
    if (err2) {
        std::cerr << "获取指纹失败: " << err2.message() << "\n";
    } else {
        std::cout << "指纹: " << fp2 << "\n";
        std::cout << "MAC: " << details2["mac"] << "\n";
    }

    std::cout << "\n--- 完整字段 (mac, hostname, cpu, memory) ---\n";
    auto [fp3, details3, err3] = license_manager::get_machine_fingerprint({"mac", "hostname", "cpu", "memory"});
    if (err3) {
        std::cerr << "获取指纹失败: " << err3.message() << "\n";
    } else {
        std::cout << "指纹: " << fp3 << "\n\n";
        std::cout << "详细信息:\n";
        for (const auto& [key, value] : details3) {
            std::cout << "  " << key << ": " << value << "\n";
        }
    }

    return 0;
}

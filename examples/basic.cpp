/**
 * License Manager C++ SDK - 最小业务接入示例
 *
 * 这个示例只演示真实业务程序最关心的流程：
 *   1. 程序启动时校验本地许可证
 *   2. 如果本地没有许可证，则提示用户输入激活码并在线激活
 *   3. 激活/校验成功后读取许可证内容，用这些字段控制软件功能
 *
 * 首次在线激活只需要激活码。RSA 公钥由激活接口返回，SDK 会缓存在本地。
 */

#include <client.hpp>
#include <config.hpp>

#include <any>
#include <chrono>
#include <ctime>
#include <iostream>
#include <map>
#include <string>

static std::string any_to_string(const std::any& value) {
    if (value.type() == typeid(std::string)) return std::any_cast<std::string>(value);
    if (value.type() == typeid(const char*)) return std::any_cast<const char*>(value);
    if (value.type() == typeid(bool)) return std::any_cast<bool>(value) ? "true" : "false";
    if (value.type() == typeid(int)) return std::to_string(std::any_cast<int>(value));
    if (value.type() == typeid(long)) return std::to_string(std::any_cast<long>(value));
    if (value.type() == typeid(double)) return std::to_string(std::any_cast<double>(value));
    return "<unsupported>";
}

static std::string time_to_string(const std::chrono::system_clock::time_point& time) {
    if (time == std::chrono::system_clock::time_point{}) return "-";

    const auto tt = std::chrono::system_clock::to_time_t(time);
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&tt));
    return buffer;
}

static void print_any_map(const char* title, const std::map<std::string, std::any>& values) {
    if (values.empty()) return;

    std::cout << "\n" << title << ":\n";
    for (const auto& [key, value] : values) {
        std::cout << "  " << key << ": " << any_to_string(value) << "\n";
    }
}

static void print_license_info(const license_manager::LicensePayload& license) {
    std::cout << "\n========== 当前许可证 ==========\n";
    std::cout << "产品:       " << license.product << "\n";
    std::cout << "版本:       " << license.version << "\n";
    std::cout << "许可证Key:  " << license.license_key << "\n";
    std::cout << "状态:       " << license.status << "\n";
    std::cout << "部署类型:   " << license.deployment_type << "\n";
    std::cout << "最大激活数: " << license.max_activations << "\n";
    std::cout << "开始时间:   " << time_to_string(license.start_date) << "\n";
    std::cout << "结束时间:   " << time_to_string(license.end_date) << "\n";
    std::cout << "过期时间:   " << time_to_string(license.expires_at) << "\n";

    // 业务程序通常读取这些扩展配置来控制功能开关、额度、模块权限等。
    print_any_map("自定义参数 custom_parameters", license.custom_parameters);
    print_any_map("功能配置 feature_config", license.feature_config);
    print_any_map("使用限制 usage_limits", license.usage_limits);
    print_any_map("其他字段 extras", license.extras);
    std::cout << "==============================\n";
}

static license_manager::Config make_config() {
    license_manager::Config config;

    // TODO: 对接时改成你的授权服务地址、产品标识和软件版本。
    config.server = "http://lm-e.cedar-v.com";
    config.product = "my-product";
    config.version = "1.0.0";

    // 本地许可证保存位置。首次激活成功后，SDK 会把许可证保存到这里。
    config.license_file_path = "license_code/license.lic";

    // 不在这里写激活码。启动后如果没有有效许可证，再让用户输入。
    // 如果你的程序想从文件读取激活码，也可以设置：
    // config.authorization_code_path = "license_code/authorization_code.txt";

    // 首次在线激活不需要配置公钥；激活接口会返回公钥并缓存。
    // 离线校验或固定公钥场景才需要设置 public_key_path/public_key_pem。

    // 硬件指纹字段用于把许可证绑定到当前设备。
    // 支持字段：
    //   mac      - 网卡 MAC 地址，常用，推荐保留
    //   hostname - 计算机名称，常用，推荐保留
    //   cpu      - CPU 型号，可提高绑定强度
    //   memory   - 物理内存大小，硬件变更时可能导致指纹变化
    //
    // 配置规则：
    //   1. 选择的字段越多，绑定越严格；硬件变化后越可能需要重新激活。
    //   2. 字段顺序不影响指纹，SDK 内部会按字段名排序后计算。
    //   3. 激活后不要随意修改字段集合，否则本地指纹会变化。
    //   4. 如果传空数组，SDK 默认使用 {"mac", "hostname"}。
    config.hardware_fields = {"mac", "hostname", "cpu"};
    config.log_level = "warn";
    return config;
}

static license_manager::Result<std::unique_ptr<license_manager::Client>>
create_client(license_manager::Config config) {
    auto result = license_manager::Client::create(config);
    if (result) return result;

    const auto err = result.error();
    const bool need_activation_code =
        err == license_manager::make_error_code(license_manager::Errc::config_auth_code_required) ||
        err == license_manager::make_error_code(license_manager::Errc::no_license_loaded);

    if (!need_activation_code) {
        return result;
    }

    std::cout << "未找到有效许可证，请输入激活码: ";
    std::getline(std::cin, config.authorization_code);

    if (config.authorization_code.empty()) {
        return license_manager::Result<std::unique_ptr<license_manager::Client>>::failure(
            license_manager::make_error_code(
                license_manager::Errc::config_auth_code_required));
    }

    return license_manager::Client::create(config);
}

int main() {
    auto result = create_client(make_config());
    if (!result) {
        std::cerr << "授权校验/激活失败: " << result.error().message() << "\n";
        return 1;
    }

    auto client = std::move(*result);

    if (auto err = client->validate()) {
        std::cerr << "许可证无效: " << err.message() << "\n";
        return 1;
    }

    const auto license = client->current_license();
    if (!license) {
        std::cerr << "没有读取到许可证信息\n";
        return 1;
    }

    print_license_info(*license);

    // 业务程序从这里开始启动自己的功能。
    // 例如根据 license->feature_config / usage_limits / custom_parameters 控制模块权限。
    client->close();
    return 0;
}

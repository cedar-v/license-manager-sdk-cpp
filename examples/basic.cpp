/**
 * Basic example for License Manager C++ SDK
 *
 * This example demonstrates:
 * 1. Creating a license client
 * 2. Checking license status
 * 3. Handling callbacks
 * 4. Running heartbeat for a period
 */

#include <client.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <spdlog/spdlog.h>

static std::string any_to_string(const std::any& a) {
    if (a.type() == typeid(std::string)) {
        return std::any_cast<std::string>(a);
    }
    if (a.type() == typeid(int)) {
        return std::to_string(std::any_cast<int>(a));
    }
    if (a.type() == typeid(bool)) {
        return std::any_cast<bool>(a) ? "true" : "false";
    }
    if (a.type() == typeid(double)) {
        return std::to_string(std::any_cast<double>(a));
    }
    return "<unsupported type>";
}

int main(int argc, char* argv[]) {
    using namespace license_manager;

    // Setup spdlog
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%L%$] %v");

    std::cout << "=== License Manager C++ SDK Basic Example ===" << std::endl;

    // Configuration
    Config config;
    config.server = "https://license.example.com";
    config.product = "edge-gateway";
    config.version = "2.3.1";
    config.authorization_code_path = "license_code/authorization_code.txt";
    config.public_key_path = "license_code/rsa_public_key.pem";
    config.hardware_fields = {"mac", "hostname"};
    config.heartbeat_interval_seconds = 10;  // Demo: 10 seconds for quick feedback
    config.log_level = "info";

    // Optional: inline configuration
    // config.authorization_code = "YOUR-AUTH-CODE-HERE";
    // config.public_key_pem = "-----BEGIN PUBLIC KEY-----\n...";

    // Optional: encryption for local storage
    // config.storage_secret = {'m', 'y', 's', 'e', 'c', 'r', 'e', 't'};

    // Optional: custom HTTP headers
    // config.http_headers["X-Custom-Header"] = "value";

    // Optional: device info sent during activation
    // config.device_info["device_id"] = "device-123";
    // config.device_info["location"] = "datacenter-1";

    // Setup callbacks
    Client::Options opts;
    opts.on_license_updated = [](const LicensePayload& lic) {
        std::cout << "[Callback] License updated!" << std::endl;
        std::cout << "  - License Key: " << lic.license_key << std::endl;
        std::cout << "  - Status: " << lic.status << std::endl;
        std::cout << "  - Expires: " << std::chrono::system_clock::to_time_t(lic.expires_at) << std::endl;
    };

    opts.on_heartbeat_error = [](const std::error_code& err) {
        std::cerr << "[Callback] Heartbeat error: " << err.message() << std::endl;
    };

    opts.on_activation_required = [](const std::string& reason) {
        std::cerr << "[Callback] Activation required: " << reason << std::endl;
    };

    // Create client
    std::cout << "\nCreating license client..." << std::endl;
    auto result = Client::create(config, opts);

    if (!result) {
        std::cerr << "Failed to create client: " << result.error().message() << std::endl;
        return 1;
    }

    auto client = std::move(*result);
    std::cout << "Client created successfully!" << std::endl;

    // Check current license
    if (auto lic = client->current_license()) {
        std::cout << "\nCurrent license:" << std::endl;
        std::cout << "  - License Key: " << lic->license_key << std::endl;
        std::cout << "  - Status: " << lic->status << std::endl;
        std::cout << "  - Max Activations: " << lic->max_activations << std::endl;

        // Print expiration
        auto expires_tt = std::chrono::system_clock::to_time_t(lic->expires_at);
        std::cout << "  - Expires: " << std::put_time(std::localtime(&expires_tt), "%Y-%m-%d %H:%M:%S") << std::endl;

        // Print custom parameters if any
        if (!lic->extras.empty()) {
            std::cout << "  - Extra data:" << std::endl;
            for (const auto& [k, v] : lic->extras) {
                std::cout << "    " << k << ": " << any_to_string(v) << std::endl;
            }
        }
    } else {
        std::cout << "\nNo license loaded yet." << std::endl;
    }

    // Validate license
    if (auto err = client->validate()) {
        std::cerr << "License validation failed: " << err.message() << std::endl;
    } else {
        std::cout << "\nLicense validation passed." << std::endl;
    }

    // Demo: run heartbeat for 35 seconds
    std::cout << "\nRunning heartbeat for 35 seconds (demo)..." << std::endl;
    std::cout << "Press Ctrl+C to exit early." << std::endl;

    auto start = std::chrono::steady_clock::now();
    auto interval = std::chrono::seconds(35);

    while (std::chrono::steady_clock::now() - start < interval) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Optional: check status periodically
        if (auto lic = client->current_license()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start).count();
            std::cout << "[" << elapsed << "s] Heartbeat running... Status: " << lic->status << std::endl;
        }
    }

    // Cleanup
    std::cout << "\nClosing client..." << std::endl;
    client->close();
    std::cout << "Done." << std::endl;

    return 0;
}

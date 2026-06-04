#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <chrono>
#include "types.hpp"
#include "errors.hpp"

namespace license_manager {

struct Config {
    // Required for online mode
    std::string server;
    std::string product;
    std::string version;

    // Authorization code (inline or file path)
    std::string authorization_code;
    std::string authorization_code_path;

    // RSA public key (inline PEM or file path). Optional for first online
    // activation when the activation API returns a public key.
    std::string public_key_pem;
    std::string public_key_path;

    // License file for offline mode
    std::string license_file_path;

    // Optional settings
    bool offline = false;
    std::string base_path;
    int heartbeat_interval_seconds = 300;  // Default 5 minutes
    int http_timeout_seconds = 15;
    std::string log_level = "info";
    std::string storage_path;
    std::vector<uint8_t> storage_secret;
    std::vector<std::string> hardware_fields = {"mac", "hostname"};
    std::map<std::string, std::string> http_headers;
    std::map<std::string, std::any> device_info;
    std::map<std::string, std::any> metadata;

    // Resolve authorization code from inline or file
    std::error_code resolve_authorization_code() {
        if (!authorization_code.empty()) {
            return {};
        }
        if (authorization_code_path.empty()) {
            return make_error_code(Errc::config_auth_code_required);
        }
        return read_file(authorization_code_path, authorization_code);
    }

    // Resolve public key from inline PEM or file
    std::error_code resolve_public_key() {
        if (!public_key_pem.empty()) {
            return {};
        }
        if (public_key_path.empty()) {
            return make_error_code(Errc::config_public_key_required);
        }
        return read_file(public_key_path, public_key_pem);
    }

    // Validate configuration
    std::error_code validate() const {
        if (product.empty()) {
            return make_error_code(Errc::config_product_required);
        }
        if (version.empty()) {
            return make_error_code(Errc::config_version_required);
        }
        if (!offline && server.empty()) {
            return make_error_code(Errc::config_server_required);
        }
        return {};
    }

    // Get heartbeat interval as duration
    std::chrono::seconds heartbeat_interval() const {
        if (heartbeat_interval_seconds <= 0) {
            return std::chrono::seconds(300);
        }
        return std::chrono::seconds(heartbeat_interval_seconds);
    }

    // Get HTTP timeout as duration
    std::chrono::seconds http_timeout() const {
        if (http_timeout_seconds <= 0) {
            return std::chrono::seconds(15);
        }
        return std::chrono::seconds(http_timeout_seconds);
    }

    // Get storage path (defaults to license_file_path)
    std::string get_storage_path() const {
        if (!storage_path.empty()) {
            return storage_path;
        }
        if (!license_file_path.empty()) {
            return license_file_path;
        }
        return "license_code/license.lic";
    }

private:
    static std::error_code read_file(const std::string& path, std::string& output) {
        FILE* fp = fopen(path.c_str(), "rb");
        if (!fp) {
            return make_error_code(Errc::config_file_read_error);
        }
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        output.resize(static_cast<size_t>(size));
        size_t read_bytes = fread(output.data(), 1, static_cast<size_t>(size), fp);
        fclose(fp);
        if (read_bytes != static_cast<size_t>(size)) {
            return make_error_code(Errc::config_file_read_error);
        }
        // Trim whitespace
        size_t start = 0;
        while (start < output.size() && std::isspace(static_cast<unsigned char>(output[start]))) {
            ++start;
        }
        size_t end = output.size();
        while (end > start && std::isspace(static_cast<unsigned char>(output[end - 1]))) {
            --end;
        }
        output = output.substr(start, end - start);
        return {};
    }
};

} // namespace license_manager

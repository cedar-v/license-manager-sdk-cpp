#pragma once

#include <string>
#include <map>
#include <optional>
#include <chrono>
#include "types.hpp"

namespace license_manager {

// LicensePayload describes the decoded content of a license file
struct LicensePayload {
    std::string product_code;
    std::string version;
    std::string license_key;
    std::string authorization_code;
    std::string authorization_code_id;
    std::string hardware_fingerprint;
    std::string status;
    std::string deployment_type;
    int max_activations = 0;
    std::map<std::string, std::any> custom_parameters;
    std::map<std::string, std::any> feature_config;
    std::map<std::string, std::any> usage_limits;
    std::chrono::system_clock::time_point start_date;
    std::chrono::system_clock::time_point end_date;
    std::chrono::system_clock::time_point expires_at;
    std::optional<std::chrono::system_clock::time_point> activated_at;
    std::optional<std::chrono::system_clock::time_point> generated_at;
    std::map<std::string, std::any> extras;
};

// LicenseEnvelope is the serialized document persisted locally
struct LicenseEnvelope {
    std::string algorithm;  // "RSA-SHA256" or "RSA-PSS-SHA256"
    std::string data;       // JSON string
    std::string signature;  // Base64 encoded signature
};

// Request for activation
struct ActivateRequest {
    std::string authorization_code;
    std::string product;
    std::string version;
    std::string hardware_fingerprint;
    std::string software_version;
    std::map<std::string, std::any> device_info;
    std::map<std::string, std::any> metadata;
};

// Response from activation
struct ActivateResponse {
    std::string license_key;
    std::string license_file;  // Base64 encoded LicenseEnvelope
    int heartbeat_interval = 0;
    std::optional<std::string> public_key;  // New RSA public key from server
    std::optional<LicensePayload> payload;
};

// Request for heartbeat
struct HeartbeatRequest {
    std::string license_key;
    std::string hardware_fingerprint;
    std::string software_version;
    std::map<std::string, std::any> usage_data;
    std::optional<std::chrono::system_clock::time_point> config_updated_at;
};

// Response from heartbeat
struct HeartbeatResponse {
    std::string status;
    std::string license_file;  // Optional, Base64 encoded
    int heartbeat_interval = 0;
    bool config_updated = false;
    std::optional<LicensePayload> payload;
};

// API error response
struct APIError {
    std::string code;
    std::string message;
    std::string timestamp;
};

// API response envelope
template<typename T>
struct APIResponse {
    std::string code;
    std::string message;
    std::optional<T> data;
};

} // namespace license_manager

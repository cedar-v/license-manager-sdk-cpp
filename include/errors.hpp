#pragma once

#include <system_error>
#include <string>
#include <cstring>

namespace license_manager {

enum class Errc {
    // Success
    success = 0,

    // Config errors (1xxx)
    config_product_required = 1001,
    config_version_required = 1002,
    config_server_required = 1003,
    config_auth_code_required = 1004,
    config_public_key_required = 1005,
    config_file_read_error = 1006,

    // Activation errors (2xxx)
    activation_http_error = 2001,
    activation_invalid_response = 2002,
    activation_server_error = 2003,
    activation_missing_license_file = 2004,

    // Validation errors (3xxx)
    validation_empty_license = 3001,
    validation_decode_error = 3002,
    validation_signature_mismatch = 3003,
    validation_expired = 3004,
    validation_fingerprint_mismatch = 3005,
    validation_unsupported_algorithm = 3006,
    validation_invalid_public_key = 3007,
    validation_parse_error = 3008,

    // Storage errors (4xxx)
    storage_read_error = 4001,
    storage_write_error = 4002,
    storage_encrypt_error = 4003,
    storage_decrypt_error = 4004,
    storage_file_not_found = 4005,

    // Heartbeat errors (5xxx)
    heartbeat_http_error = 5001,
    heartbeat_server_error = 5002,

    // Hardware errors (6xxx)
    hardware_fingerprint_error = 6001,

    // Common errors (9xxx)
    invalid_operation = 9001,
    no_license_loaded = 9002,
    invalid_json = 9003,
    http_timeout = 9004,
};

class ErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override {
        return "license-manager";
    }

    std::string message(int ev) const override {
        switch (static_cast<Errc>(ev)) {
            case Errc::success:
                return "Success";
            // Config errors
            case Errc::config_product_required:
                return "Config: product is required";
            case Errc::config_version_required:
                return "Config: version is required";
            case Errc::config_server_required:
                return "Config: server URL is required for online mode";
            case Errc::config_auth_code_required:
                return "Config: authorization code is required";
            case Errc::config_public_key_required:
                return "Config: public key is required";
            case Errc::config_file_read_error:
                return "Config: failed to read config file";
            // Activation errors
            case Errc::activation_http_error:
                return "Activation: HTTP request failed";
            case Errc::activation_invalid_response:
                return "Activation: invalid server response";
            case Errc::activation_server_error:
                return "Activation: server returned error";
            case Errc::activation_missing_license_file:
                return "Activation: response missing license file";
            // Validation errors
            case Errc::validation_empty_license:
                return "Validation: license file is empty";
            case Errc::validation_decode_error:
                return "Validation: failed to decode license";
            case Errc::validation_signature_mismatch:
                return "Validation: signature mismatch";
            case Errc::validation_expired:
                return "Validation: license has expired";
            case Errc::validation_fingerprint_mismatch:
                return "Validation: hardware fingerprint mismatch";
            case Errc::validation_unsupported_algorithm:
                return "Validation: unsupported signature algorithm";
            case Errc::validation_invalid_public_key:
                return "Validation: invalid RSA public key";
            case Errc::validation_parse_error:
                return "Validation: failed to parse license data";
            // Storage errors
            case Errc::storage_read_error:
                return "Storage: failed to read license file";
            case Errc::storage_write_error:
                return "Storage: failed to write license file";
            case Errc::storage_encrypt_error:
                return "Storage: encryption failed";
            case Errc::storage_decrypt_error:
                return "Storage: decryption failed";
            case Errc::storage_file_not_found:
                return "Storage: license file not found";
            // Heartbeat errors
            case Errc::heartbeat_http_error:
                return "Heartbeat: HTTP request failed";
            case Errc::heartbeat_server_error:
                return "Heartbeat: server returned error";
            // Hardware errors
            case Errc::hardware_fingerprint_error:
                return "Hardware: failed to collect fingerprint";
            // Common errors
            case Errc::invalid_operation:
                return "Invalid operation";
            case Errc::no_license_loaded:
                return "No license has been loaded";
            case Errc::invalid_json:
                return "Invalid JSON format";
            case Errc::http_timeout:
                return "HTTP request timeout";
            default:
                return "Unknown error";
        }
    }

    bool equivalent(const std::error_code& code, int condition) const noexcept override {
        return *this == code.category() &&
               static_cast<int>(code.value()) == condition;
    }
};

inline const ErrorCategory& GetErrorCategory() {
    static ErrorCategory instance;
    return instance;
}

inline std::error_code make_error_code(Errc e) {
    return std::error_code(static_cast<int>(e), GetErrorCategory());
}

inline std::error_code make_error_code(Errc e, const std::string& /*message*/) {
    return std::error_code(static_cast<int>(e), GetErrorCategory());
}

} // namespace license_manager

namespace std {
    template<>
    struct is_error_code_enum<license_manager::Errc> : true_type {};
}

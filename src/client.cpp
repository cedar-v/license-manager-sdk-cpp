#include "client.hpp"
#include "activation.hpp"
#include "heartbeat.hpp"
#include "validator.hpp"
#include <utility>
#include <cstring>

namespace license_manager {

std::expected<std::unique_ptr<Client>, std::error_code>
Client::create(const Config& config, Options opts) {
    auto client = std::unique_ptr<Client>(new Client());

    auto err = client->initialize(config, opts);
    if (err) {
        return std::unexpected(err);
    }

    return client;
}

Client::~Client() {
    close();
}

std::error_code Client::initialize(const Config& config, Options& opts) {
    config_ = config;

    // Validate config
    auto err = config_.validate();
    if (err) {
        return err;
    }

    // Resolve public key
    err = config_.resolve_public_key();
    if (err) {
        return err;
    }

    // Resolve authorization code (online mode only)
    if (!config_.offline) {
        err = config_.resolve_authorization_code();
        if (err) {
            return err;
        }
    }

    // Setup logger
    if (opts.logger) {
        logger_ = std::move(opts.logger);
    } else {
        logger_ = std::make_shared<SpdlogLogger>(parse_log_level(config_.log_level));
    }

    // Setup hardware provider
    if (opts.hardware_provider) {
        hardware_ = std::move(opts.hardware_provider);
    } else {
        hardware_ = std::make_shared<DefaultHardwareProvider>(config_.hardware_fields);
    }

    // Collect fingerprint
    auto [fingerprint, details, fp_err] = hardware_->fingerprint();
    if (fp_err) {
        logger_->error("Failed to collect hardware fingerprint");
        return fp_err;
    }
    fingerprint_ = std::move(fingerprint);
    fingerprint_details_ = std::move(details);
    logger_->infof("Hardware fingerprint: %s", fingerprint_.c_str());

    // Setup storage
    if (opts.storage) {
        storage_ = std::move(opts.storage);
    } else {
        storage_ = std::make_shared<FileStorage>(
            config_.get_storage_path(),
            config_.storage_secret
        );
    }

    // Setup validator
    try {
        validator_ = std::make_shared<Validator>(config_.public_key_pem);
    } catch (const std::exception& e) {
        logger_->errorf("Failed to create validator: %s", e.what());
        return make_error_code(Errc::validation_invalid_public_key);
    }

    // Setup activation service
    heartbeat_service_ = std::make_shared<HeartbeatService>(config_, logger_);

    // Store callbacks
    on_license_updated_ = std::move(opts.on_license_updated);
    on_heartbeat_error_ = std::move(opts.on_heartbeat_error);
    on_activation_required_ = std::move(opts.on_activation_required);

    // Bootstrap: try loading existing license
    err = load_existing_license();
    if (!err && current_license_.has_value()) {
        logger_->infof("Loaded cached license, expires at: %s",
            std::chrono::system_clock::to_time_t(current_license_->expires_at));

        if (!config_.offline) {
            err = start_heartbeat();
            if (err) {
                logger_->warnf("Failed to start heartbeat: %s", err.message().c_str());
            }
        }
        valid_ = true;
        return {};
    }

    // No valid license loaded
    if (config_.offline) {
        logger_->error("Offline mode requires a pre-loaded license");
        return make_error_code(Errc::no_license_loaded);
    }

    // Try activation
    err = perform_activation();
    if (err) {
        return err;
    }

    // Start heartbeat
    err = start_heartbeat();
    if (err) {
        logger_->warnf("Failed to start heartbeat: %s", err.message().c_str());
    }

    valid_ = true;
    return {};
}

std::error_code Client::load_existing_license() {
    auto [data, err] = storage_->load();
    if (err) {
        if (err == make_error_code(Errc::storage_file_not_found)) {
            return {};  // Not an error, just no file exists yet
        }
        return err;
    }

    auto [payload, verify_err] = validate_and_store(data);
    if (verify_err) {
        logger_->warnf("Cached license invalid: %s", verify_err.message().c_str());
        return {};  // Not an error, will try activation
    }

    current_license_ = payload;
    return {};
}

std::error_code Client::perform_activation() {
    logger_->infof("Activating with server: %s", config_.server.c_str());

    // Build device info
    std::map<std::string, std::any> device_info = config_.device_info;
    for (const auto& [k, v] : fingerprint_details_) {
        device_info["hardware_" + k] = v;
    }

    ActivateRequest request;
    request.authorization_code = config_.authorization_code;
    request.product = config_.product;
    request.version = config_.version;
    request.hardware_fingerprint = fingerprint_;
    request.device_info = device_info;
    request.metadata = config_.metadata;

    ActivationService service(config_, logger_);
    auto [response, err] = service.activate(request);

    if (err) {
        logger_->errorf("Activation failed: %s", err.message().c_str());
        if (on_activation_required_) {
            on_activation_required_(err.message());
        }
        return err;
    }

    // Apply the license file
    err = apply_license_file(response.license_file);
    if (err) {
        return err;
    }

    logger_->infof("Activation successful, license key: %s",
        current_license_->license_key);

    return {};
}

std::error_code Client::apply_license_file(const std::string& base64_license) {
    // Base64 decode
    std::vector<uint8_t> decoded;
    auto base64_decode = [](const std::string& encoded) -> std::pair<std::vector<uint8_t>, std::error_code> {
        static const char* table =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        std::vector<uint8_t> result;
        int val = 0;
        int bits = -8;

        for (char c : encoded) {
            if (c == '=') break;
            if (c == ' ' || c == '\n' || c == '\r') continue;

            const char* p = std::strchr(table, c);
            if (!p) {
                return {{}, make_error_code(Errc::validation_decode_error)};
            }

            val = (val << 6) | (p - table);
            bits += 6;

            if (bits >= 0) {
                result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
                bits -= 8;
            }
        }

        return {result, {}};
    };

    auto [decoded_data, decode_err] = base64_decode(base64_license);
    if (decode_err) {
        return decode_err;
    }

    // Validate and store
    auto [payload, verify_err] = validate_and_store(decoded_data);
    if (verify_err) {
        return verify_err;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    current_license_ = payload;

    if (on_license_updated_) {
        on_license_updated_(*current_license_);
    }

    return {};
}

std::pair<LicensePayload, std::error_code>
Client::validate_and_store(const std::vector<uint8_t>& data) {
    // Normalize: trim whitespace, detect if base64 encoded
    std::vector<uint8_t> normalized = normalize_license_bytes(data);

    // Verify
    auto [payload, err] = validator_->verify(normalized, fingerprint_);
    if (err) {
        return {{}, err};
    }

    // Store
    err = storage_->save(normalized);
    if (err) {
        logger_->warnf("Failed to persist license: %s", err.message().c_str());
    }

    return {payload, {}};
}

std::vector<uint8_t> Client::normalize_license_bytes(const std::vector<uint8_t>& raw) const {
    // Trim whitespace at start
    size_t start = 0;
    while (start < raw.size() &&
           (raw[start] == ' ' || raw[start] == '\n' ||
            raw[start] == '\r' || raw[start] == '\t')) {
        ++start;
    }

    // Check if JSON
    if (start < raw.size() && raw[start] == '{') {
        return std::vector<uint8_t>(raw.begin() + start, raw.end());
    }

    // Base64 decode
    std::string encoded(raw.begin() + start, raw.end());
    while (!encoded.empty() && std::isspace(encoded.back())) {
        encoded.pop_back();
    }

    // Simple base64 decode
    static const char* table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::vector<uint8_t> result;
    int val = 0;
    int bits = -8;

    for (char c : encoded) {
        if (c == '=') break;

        const char* p = std::strchr(table, c);
        if (!p) continue;

        val = (val << 6) | (p - table);
        bits += 6;

        if (bits >= 0) {
            result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }

    // Trim whitespace from result
    while (!result.empty() &&
           (result.back() == ' ' || result.back() == '\n' ||
            result.back() == '\r' || result.back() == '\t')) {
        result.pop_back();
    }

    return result;
}

std::error_code Client::start_heartbeat() {
    if (!current_license_ || current_license_->license_key.empty()) {
        logger_->warn("Heartbeat skipped: no license key available");
        return {};
    }

    HeartbeatRequest request;
    request.license_key = current_license_->license_key;
    request.hardware_fingerprint = fingerprint_;

    auto on_update = [this](const HeartbeatResponse& resp) {
        if (!resp.license_file.empty()) {
            auto err = apply_license_file(resp.license_file);
            if (err) {
                logger_->warnf("Failed to apply license from heartbeat: %s", err.message().c_str());
            }
        }
        if (resp.status == "activation_required" && on_activation_required_) {
            on_activation_required_("Heartbeat requested reactivation");
        }
    };

    heartbeat_manager_ = std::make_shared<HeartbeatManager>(
        heartbeat_service_,
        request,
        config_.heartbeat_interval(),
        on_update,
        [this](const std::error_code& err) {
            if (on_heartbeat_error_) {
                on_heartbeat_error_(err);
            }
        },
        logger_
    );

    heartbeat_manager_->start();
    return {};
}

std::error_code Client::validate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!current_license_) {
        return make_error_code(Errc::no_license_loaded);
    }

    auto now = std::chrono::system_clock::now();
    if (now > current_license_->expires_at) {
        return make_error_code(Errc::validation_expired);
    }

    return {};
}

std::optional<LicensePayload> Client::current_license() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!current_license_) {
        return std::nullopt;
    }
    return *current_license_;
}

std::optional<std::string> Client::license_key() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!current_license_) {
        return std::nullopt;
    }
    return current_license_->license_key;
}

void Client::pause_heartbeat() {
    if (heartbeat_manager_) {
        heartbeat_manager_->pause();
    }
}

void Client::resume_heartbeat() {
    if (heartbeat_manager_) {
        heartbeat_manager_->resume();
    }
}

std::error_code Client::activate() {
    return perform_activation();
}

std::error_code Client::send_heartbeat() {
    if (!current_license_) {
        return make_error_code(Errc::no_license_loaded);
    }

    HeartbeatRequest request;
    request.license_key = current_license_->license_key;
    request.hardware_fingerprint = fingerprint_;

    auto [response, err] = heartbeat_service_->send(request);
    if (err) {
        return err;
    }

    if (!response.license_file.empty()) {
        return apply_license_file(response.license_file);
    }

    return {};
}

void Client::close() {
    if (heartbeat_manager_) {
        heartbeat_manager_->stop();
        heartbeat_manager_.reset();
    }
}

} // namespace license_manager

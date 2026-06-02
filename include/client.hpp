#pragma once

#include <memory>
#include <optional>
#include <functional>
#include <expected>
#include "types.hpp"
#include "errors.hpp"
#include "config.hpp"
#include "models.hpp"
#include "logger.hpp"
#include "storage.hpp"
#include "hardware.hpp"

namespace license_manager {

class Client {
public:
    // Callbacks
    using LicenseUpdatedCallback = std::function<void(const LicensePayload&)>;
    using HeartbeatErrorCallback = std::function<void(const std::error_code&)>;
    using ActivationRequiredCallback = std::function<void(const std::string&)>;

    // Options for client construction
    struct Options {
        std::shared_ptr<Logger> logger;
        std::shared_ptr<HardwareProvider> hardware_provider;
        std::shared_ptr<Storage> storage;
        LicenseUpdatedCallback on_license_updated;
        HeartbeatErrorCallback on_heartbeat_error;
        ActivationRequiredCallback on_activation_required;
    };

    // Factory method returning expected
    static std::expected<std::unique_ptr<Client>, std::error_code>
    create(const Config& config, Options opts = {});

    // Destructor
    ~Client();

    // Disable copy and move (owned via unique_ptr)
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) noexcept = delete;
    Client& operator=(Client&&) noexcept = delete;

    // Validate current license
    std::error_code validate() const;

    // Get current license copy
    std::optional<LicensePayload> current_license() const;

    // Get license key
    std::optional<std::string> license_key() const;

    // Pause heartbeat temporarily
    void pause_heartbeat();

    // Resume heartbeat after pause
    void resume_heartbeat();

    // Manually trigger activation
    std::error_code activate();

    // Manually send heartbeat once
    std::error_code send_heartbeat();

    // Close client and stop heartbeat thread
    void close();

    // Check if client is valid and has a valid license
    bool is_valid() const { return valid_.load(); }

private:
    Client() = default;

    std::error_code initialize(const Config& config, Options& opts);
    std::error_code load_existing_license();
    std::error_code perform_activation();
    std::error_code start_heartbeat();
    std::error_code apply_license_file(const std::string& base64_license);
    std::pair<LicensePayload, std::error_code> validate_and_store(const std::vector<uint8_t>& data);
    std::vector<uint8_t> normalize_license_bytes(const std::vector<uint8_t>& raw) const;

    Config config_;
    std::shared_ptr<Logger> logger_;
    std::shared_ptr<HardwareProvider> hardware_;
    std::shared_ptr<Storage> storage_;
    std::shared_ptr<class HeartbeatService> heartbeat_service_;
    std::shared_ptr<class HeartbeatManager> heartbeat_manager_;
    std::shared_ptr<class Validator> validator_;

    std::string fingerprint_;
    std::map<std::string, std::string> fingerprint_details_;
    std::optional<LicensePayload> current_license_;
    mutable std::mutex mutex_;

    std::atomic<bool> valid_{false};

    LicenseUpdatedCallback on_license_updated_;
    HeartbeatErrorCallback on_heartbeat_error_;
    ActivationRequiredCallback on_activation_required_;
};

} // namespace license_manager

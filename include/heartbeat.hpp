#pragma once

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <functional>
#include "types.hpp"
#include "errors.hpp"
#include "config.hpp"
#include "models.hpp"
#include "logger.hpp"

namespace license_manager {

class HeartbeatService {
public:
    HeartbeatService(const Config& config, std::shared_ptr<Logger> logger);
    ~HeartbeatService();

    std::pair<HeartbeatResponse, std::error_code> send(const HeartbeatRequest& request);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

class HeartbeatManager {
public:
    using LicenseUpdatedCallback = std::function<void(const HeartbeatResponse&)>;
    using ErrorCallback = std::function<void(const std::error_code&)>;

    HeartbeatManager(
        std::shared_ptr<HeartbeatService> service,
        HeartbeatRequest request,
        std::chrono::seconds interval,
        LicenseUpdatedCallback on_license_updated,
        ErrorCallback on_error,
        std::shared_ptr<Logger> logger
    );

    ~HeartbeatManager();

    void start();
    void stop();
    void pause();
    void resume();

    bool is_running() const { return running_.load(); }
    bool is_paused() const { return paused_.load(); }

private:
    void loop();

    std::shared_ptr<HeartbeatService> service_;
    HeartbeatRequest request_;
    std::chrono::seconds interval_;
    LicenseUpdatedCallback on_license_updated_;
    ErrorCallback on_error_;
    std::shared_ptr<Logger> logger_;

    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::atomic<bool> stop_requested_{false};
    std::thread thread_;
    mutable std::mutex mutex_;
};

} // namespace license_manager

#include "heartbeat.hpp"
#include "util.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sstream>

using json = nlohmann::json;

namespace license_manager {

struct HeartbeatService::Impl {
    CURL* curl = nullptr;
    std::string base_url;
    std::map<std::string, std::string> headers;
    std::shared_ptr<Logger> logger;
    long timeout_seconds = 15;

    Impl(const Config& config, std::shared_ptr<Logger> logger_ptr)
        : logger(std::move(logger_ptr)) {
        curl = curl_easy_init();
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }

        // Build base URL
        std::string base = config.server;
        if (!base.empty() && base.back() == '/') {
            base.pop_back();
        }
        if (!config.base_path.empty()) {
            base += "/" + config.base_path;
        }
        base_url = base + "/api/v1/heartbeat";
        headers = config.http_headers;
        timeout_seconds = config.http_timeout_seconds > 0 ? config.http_timeout_seconds : 15;
    }

    ~Impl() {
        if (curl) {
            curl_easy_cleanup(curl);
        }
    }
};

HeartbeatService::HeartbeatService(const Config& config, std::shared_ptr<Logger> logger)
    : pimpl_(std::make_unique<Impl>(config, logger)) {}

HeartbeatService::~HeartbeatService() = default;

namespace {
size_t heartbeat_write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), realsize);
    return realsize;
}
}  // namespace

std::pair<HeartbeatResponse, std::error_code>
HeartbeatService::send(const HeartbeatRequest& request) {
    HeartbeatResponse response;

    if (!pimpl_->curl) {
        return {response, make_error_code(Errc::heartbeat_http_error)};
    }

    // Build JSON body
    json body;
    body["license_key"] = request.license_key;
    body["hardware_fingerprint"] = request.hardware_fingerprint;
    if (!request.software_version.empty()) {
        body["software_version"] = request.software_version;
    }
    if (!request.usage_data.empty()) {
        for (const auto& [k, v] : request.usage_data) {
            body["usage_data"][k] = any_to_json(v);
        }
    }

    std::string json_body = body.dump();

    // Reset curl handle
    curl_easy_reset(pimpl_->curl);
    curl_easy_setopt(pimpl_->curl, CURLOPT_URL, pimpl_->base_url.c_str());
    curl_easy_setopt(pimpl_->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(pimpl_->curl, CURLOPT_POSTFIELDS, json_body.c_str());
    curl_easy_setopt(pimpl_->curl, CURLOPT_WRITEFUNCTION, heartbeat_write_callback);
    std::string response_body;
    curl_easy_setopt(pimpl_->curl, CURLOPT_WRITEDATA, &response_body);
    curl_easy_setopt(pimpl_->curl, CURLOPT_TIMEOUT, pimpl_->timeout_seconds);
    curl_easy_setopt(pimpl_->curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(pimpl_->curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(pimpl_->curl, CURLOPT_SSL_VERIFYHOST, 2L);
#ifdef _WIN32
    // Use the Windows root certificate store when libcurl is built with an
    // OpenSSL-compatible TLS backend. This keeps HTTPS verification enabled
    // without requiring the application to ship or configure a CA bundle.
    curl_easy_setopt(pimpl_->curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif

    // Set headers
    struct curl_slist* header_list = nullptr;
    header_list = curl_slist_append(header_list, "Content-Type: application/json");
    for (const auto& [k, v] : pimpl_->headers) {
        std::string header = k + ": " + v;
        header_list = curl_slist_append(header_list, header.c_str());
    }
    curl_easy_setopt(pimpl_->curl, CURLOPT_HTTPHEADER, header_list);

    pimpl_->logger->debugf("Heartbeat request to: %s", pimpl_->base_url.c_str());

    CURLcode res = curl_easy_perform(pimpl_->curl);

    if (header_list) {
        curl_slist_free_all(header_list);
    }

    if (res != CURLE_OK) {
        pimpl_->logger->errorf("Heartbeat HTTP error: %s", curl_easy_strerror(res));
        return {response, make_error_code(Errc::heartbeat_http_error)};
    }

    long http_code = 0;
    curl_easy_getinfo(pimpl_->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code >= 300) {
        pimpl_->logger->errorf("Heartbeat HTTP error: code=%ld, body=%s", http_code, response_body.c_str());
        return {response, make_error_code(Errc::heartbeat_http_error)};
    }

    // Parse response
    try {
        auto resp_json = json::parse(response_body);

        std::string code = resp_json.value("code", "");
        std::string message = resp_json.value("message", "");

        if (code != "000000") {
            pimpl_->logger->errorf("Heartbeat server error: %s (%s)", message.c_str(), code.c_str());
            return {response, make_error_code(Errc::heartbeat_server_error)};
        }

        if (resp_json.contains("data") && !resp_json["data"].is_null()) {
            const auto& data = resp_json["data"];
            response.status = data.value("status", "");
            response.license_file = data.value("license_file", "");
            response.heartbeat_interval = data.value("heartbeat_interval", 0);
            response.config_updated = data.value("config_updated", false);
        }

        pimpl_->logger->debug("Heartbeat successful");
        return {response, {}};

    } catch (const json::parse_error& e) {
        pimpl_->logger->errorf("Heartbeat JSON parse error: %s", e.what());
        return {response, make_error_code(Errc::activation_invalid_response)};
    }
}

// HeartbeatManager implementation
HeartbeatManager::HeartbeatManager(
    std::shared_ptr<HeartbeatService> service,
    HeartbeatRequest request,
    std::chrono::seconds interval,
    LicenseUpdatedCallback on_license_updated,
    ErrorCallback on_error,
    std::shared_ptr<Logger> logger)
    : service_(std::move(service))
    , request_(std::move(request))
    , interval_(interval)
    , on_license_updated_(std::move(on_license_updated))
    , on_error_(std::move(on_error))
    , logger_(std::move(logger)) {}

HeartbeatManager::~HeartbeatManager() {
    stop();
}

void HeartbeatManager::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_.load()) {
        return;
    }
    running_ = true;
    paused_ = false;
    stop_requested_ = false;
    thread_ = std::thread(&HeartbeatManager::loop, this);
}

void HeartbeatManager::stop() {
    stop_requested_ = true;
    if (thread_.joinable()) {
        thread_.join();
    }
    running_ = false;
}

void HeartbeatManager::pause() {
    paused_ = true;
}

void HeartbeatManager::resume() {
    paused_ = false;
}

void HeartbeatManager::loop() {
    auto current_interval = interval_;

    while (!stop_requested_.load()) {
        // Wait for interval
        auto deadline = std::chrono::steady_clock::now() + current_interval;

        while (!stop_requested_.load() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (stop_requested_.load()) break;
        }

        if (stop_requested_.load()) break;

        // Check if paused
        if (paused_.load()) {
            continue;
        }

        // Send heartbeat
        auto [resp, err] = service_->send(request_);

        if (err) {
            // Exponential backoff
            current_interval = current_interval * 2;
            if (current_interval > std::chrono::minutes(30)) {
                current_interval = std::chrono::minutes(30);
            }
            if (current_interval < std::chrono::seconds(30)) {
                current_interval = std::chrono::seconds(30);
            }

            logger_->warnf("Heartbeat failed: %s", err.message().c_str());
            if (on_error_) {
                on_error_(err);
            }
            continue;
        }

        // Reset interval on success
        current_interval = interval_;

        // Handle response
        if (!resp.license_file.empty() && on_license_updated_) {
            logger_->info("License updated from heartbeat");
            on_license_updated_(resp);
        }

        // Update interval from response if provided
        if (resp.heartbeat_interval > 0) {
            current_interval = std::chrono::seconds(resp.heartbeat_interval);
        }
    }
}

} // namespace license_manager

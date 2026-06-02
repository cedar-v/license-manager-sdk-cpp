#include "activation.hpp"
#include "util.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sstream>

using json = nlohmann::json;

namespace license_manager {

struct ActivationService::Impl {
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
        base_url = base + "/api/v1/activate";
        headers = config.http_headers;
        timeout_seconds = config.http_timeout_seconds > 0 ? config.http_timeout_seconds : 15;
    }

    ~Impl() {
        if (curl) {
            curl_easy_cleanup(curl);
        }
    }
};

ActivationService::ActivationService(const Config& config, std::shared_ptr<Logger> logger)
    : pimpl_(std::make_unique<Impl>(config, logger)) {}

ActivationService::~ActivationService() = default;

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), realsize);
    return realsize;
}

std::pair<ActivateResponse, std::error_code>
ActivationService::activate(const ActivateRequest& request) {
    ActivateResponse response;

    if (!pimpl_->curl) {
        return {response, make_error_code(Errc::activation_http_error)};
    }

    // Build JSON body
    json body;
    body["authorization_code"] = request.authorization_code;
    body["product"] = request.product;
    body["version"] = request.version;
    body["hardware_fingerprint"] = request.hardware_fingerprint;
    if (!request.software_version.empty()) {
        body["software_version"] = request.software_version;
    }
    if (!request.device_info.empty()) {
        for (const auto& [k, v] : request.device_info) {
            body["device_info"][k] = any_to_json(v);
        }
    }
    if (!request.metadata.empty()) {
        for (const auto& [k, v] : request.metadata) {
            body["metadata"][k] = any_to_json(v);
        }
    }

    std::string json_body = body.dump();

    // Reset curl handle
    curl_easy_reset(pimpl_->curl);
    curl_easy_setopt(pimpl_->curl, CURLOPT_URL, pimpl_->base_url.c_str());
    curl_easy_setopt(pimpl_->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(pimpl_->curl, CURLOPT_POSTFIELDS, json_body.c_str());
    curl_easy_setopt(pimpl_->curl, CURLOPT_WRITEFUNCTION, write_callback);
    std::string response_body;
    curl_easy_setopt(pimpl_->curl, CURLOPT_WRITEDATA, &response_body);
    curl_easy_setopt(pimpl_->curl, CURLOPT_TIMEOUT, pimpl_->timeout_seconds);
    curl_easy_setopt(pimpl_->curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(pimpl_->curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(pimpl_->curl, CURLOPT_SSL_VERIFYHOST, 2L);

    // Set headers
    struct curl_slist* header_list = nullptr;
    header_list = curl_slist_append(header_list, "Content-Type: application/json");
    for (const auto& [k, v] : pimpl_->headers) {
        std::string header = k + ": " + v;
        header_list = curl_slist_append(header_list, header.c_str());
    }
    curl_easy_setopt(pimpl_->curl, CURLOPT_HTTPHEADER, header_list);

    pimpl_->logger->debugf("Activation request to: %s", pimpl_->base_url.c_str());

    CURLcode res = curl_easy_perform(pimpl_->curl);

    if (header_list) {
        curl_slist_free_all(header_list);
    }

    if (res != CURLE_OK) {
        pimpl_->logger->errorf("Activation HTTP error: %s", curl_easy_strerror(res));
        return {response, make_error_code(Errc::activation_http_error)};
    }

    long http_code = 0;
    curl_easy_getinfo(pimpl_->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code >= 300) {
        pimpl_->logger->errorf("Activation HTTP error: code=%ld, body=%s", http_code, response_body.c_str());
        return {response, make_error_code(Errc::activation_http_error)};
    }

    // Parse response
    try {
        auto resp_json = json::parse(response_body);

        std::string code = resp_json.value("code", "");
        std::string message = resp_json.value("message", "");

        if (code != "000000") {
            pimpl_->logger->errorf("Activation server error: %s (%s)", message.c_str(), code.c_str());
            return {response, make_error_code(Errc::activation_server_error)};
        }

        if (resp_json.contains("data") && !resp_json["data"].is_null()) {
            const auto& data = resp_json["data"];
            response.license_key = data.value("license_key", "");
            response.license_file = data.value("license_file", "");
            response.heartbeat_interval = data.value("heartbeat_interval", 0);
        }

        if (response.license_file.empty()) {
            pimpl_->logger->error("Activation response missing license_file");
            return {response, make_error_code(Errc::activation_missing_license_file)};
        }

        pimpl_->logger->info("Activation successful");
        return {response, {}};

    } catch (const json::parse_error& e) {
        pimpl_->logger->errorf("Activation JSON parse error: %s", e.what());
        return {response, make_error_code(Errc::activation_invalid_response)};
    }
}

} // namespace license_manager

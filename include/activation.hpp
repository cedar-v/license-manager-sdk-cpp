#pragma once

#include <string>
#include <memory>
#include <curl/curl.h>
#include "types.hpp"
#include "errors.hpp"
#include "config.hpp"
#include "models.hpp"
#include "logger.hpp"

namespace license_manager {

class ActivationService {
public:
    ActivationService(const Config& config, std::shared_ptr<Logger> logger);
    ~ActivationService();

    std::pair<ActivateResponse, std::error_code> activate(const ActivateRequest& request);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace license_manager

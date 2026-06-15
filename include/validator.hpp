#pragma once

#include <string>
#include <memory>
#include <vector>
#include "types.hpp"
#include "errors.hpp"
#include "models.hpp"

namespace license_manager {

class Validator {
public:
    explicit Validator(const std::string& public_key_pem);
    ~Validator();

    std::pair<LicensePayload, std::error_code> verify_license(
        const std::vector<uint8_t>& license_data,
        const std::string& expected_fingerprint
    );

    std::pair<LicensePayload, std::error_code> verify_license_base64(
        const std::string& base64_license,
        const std::string& expected_fingerprint
    );

    void set_public_key(const std::string& public_key_pem);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace license_manager

#pragma once

#include <string>
#include <map>
#include <memory>
#include <vector>
#include <tuple>
#include "types.hpp"
#include "errors.hpp"

namespace license_manager {

class HardwareProvider {
public:
    virtual ~HardwareProvider() = default;

    // Returns: fingerprint_hash, fingerprint_details, error
    virtual std::tuple<std::string, std::map<std::string, std::string>, std::error_code>
    fingerprint() = 0;
};

class DefaultHardwareProvider : public HardwareProvider {
public:
    explicit DefaultHardwareProvider(std::vector<std::string> fields = {"mac", "hostname"});

    std::tuple<std::string, std::map<std::string, std::string>, std::error_code>
    fingerprint() override;

private:
    std::vector<std::string> fields_;

    std::string get_hostname() const;
    std::string get_mac_address() const;
    std::string get_cpu_info() const;
    std::string get_memory_info() const;
};

} // namespace license_manager

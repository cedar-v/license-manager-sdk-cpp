#pragma once

#include <string>
#include <map>
#include <memory>
#include <vector>
#include <tuple>
#include <system_error>
#include "types.hpp"
#include "errors.hpp"

namespace license_manager {

class DefaultHardwareProvider;

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

//=============================================================================
// Standalone API: Get machine fingerprint without creating a Client
//=============================================================================

// Get the hardware fingerprint of the current machine.
// This is a convenience function that creates a DefaultHardwareProvider internally.
// Returns: {fingerprint_hash, fingerprint_details, error}
//
// Example:
//   auto [fp, details, err] = get_machine_fingerprint({"mac", "hostname"});
//   if (!err) std::cout << fp << std::endl;
inline std::tuple<std::string, std::map<std::string, std::string>, std::error_code>
get_machine_fingerprint(const std::vector<std::string>& fields = {"mac", "hostname"}) {
    DefaultHardwareProvider provider(fields);
    return provider.fingerprint();
}

} // namespace license_manager

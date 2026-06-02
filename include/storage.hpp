#pragma once

#include <string>
#include <vector>
#include <span>
#include <memory>
#include <optional>
#include "types.hpp"
#include "errors.hpp"

namespace license_manager {

class Storage {
public:
    virtual ~Storage() = default;

    // Save license data
    virtual std::error_code save(std::span<const uint8_t> data) = 0;

    // Load license data
    virtual std::pair<std::vector<uint8_t>, std::error_code> load() = 0;

    // Delete license data
    virtual std::error_code remove() = 0;
};

class FileStorage : public Storage {
public:
    FileStorage(std::string path, std::vector<uint8_t> secret = {});
    FileStorage(std::string path, std::span<const uint8_t> secret = {});

    std::error_code save(std::span<const uint8_t> data) override;
    std::pair<std::vector<uint8_t>, std::error_code> load() override;
    std::error_code remove() override;

    const std::string& path() const { return path_; }

private:
    std::vector<uint8_t> maybe_encrypt(std::span<const uint8_t> data) const;
    std::optional<std::vector<uint8_t>> maybe_decrypt(std::span<const uint8_t> data) const;
    std::error_code write_atomic(const std::string& path, std::span<const uint8_t> data);

    std::string path_;
    std::vector<uint8_t> secret_;
};

} // namespace license_manager

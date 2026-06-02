#pragma once

#include <any>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace license_manager {

json any_to_json(const std::any& a);

} // namespace license_manager

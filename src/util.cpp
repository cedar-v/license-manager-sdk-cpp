#include "util.hpp"
#include <any>

namespace license_manager {

json any_to_json(const std::any& a) {
    if (a.type() == typeid(std::string)) {
        return std::any_cast<std::string>(a);
    }
    if (a.type() == typeid(int)) {
        return std::any_cast<int>(a);
    }
    if (a.type() == typeid(bool)) {
        return std::any_cast<bool>(a);
    }
    if (a.type() == typeid(double)) {
        return std::any_cast<double>(a);
    }
    if (a.type() == typeid(int64_t)) {
        return std::any_cast<int64_t>(a);
    }
    return nullptr;
}

} // namespace license_manager

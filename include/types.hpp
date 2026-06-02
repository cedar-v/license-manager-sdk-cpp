#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <optional>
#include <any>
#include <memory>
#include <span>
#include <functional>

namespace license_manager {

// Forward declarations
class HardwareProvider;
class Storage;
class Logger;

// Re-export common types
using String = std::string;
using StringView = std::string_view;
using Bytes = std::vector<uint8_t>;
using Milliseconds = std::chrono::milliseconds;
using Seconds = std::chrono::seconds;
using Minutes = std::chrono::minutes;

template<typename T>
using Optional = std::optional<T>;

template<typename T>
using Vector = std::vector<T>;

template<typename K, typename V>
using Map = std::map<K, V>;

template<typename T>
using Span = std::span<T>;

template<typename T>
using Function = std::function<T>;

template<typename T>
using SharedPtr = std::shared_ptr<T>;

template<typename T>
using UniquePtr = std::unique_ptr<T>;

using SystemTime = std::chrono::system_clock::time_point;

// Common callback types
using StringCallback = Function<void(const String&)>;
using ErrorCallback = Function<void(int error_code, const String& message)>;

} // namespace license_manager

#pragma once

#include <string>
#include <memory>
#include <cstdarg>
#include <cstdio>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace license_manager {

enum class LogLevel {
    debug,
    info,
    warn,
    error
};

class Logger {
public:
    virtual ~Logger() = default;

    virtual void debug(const std::string& message) = 0;
    virtual void info(const std::string& message) = 0;
    virtual void warn(const std::string& message) = 0;
    virtual void error(const std::string& message) = 0;

    virtual void debugf(const char* format, ...) = 0;
    virtual void infof(const char* format, ...) = 0;
    virtual void warnf(const char* format, ...) = 0;
    virtual void errorf(const char* format, ...) = 0;
};

class SpdlogLogger : public Logger {
public:
    explicit SpdlogLogger(LogLevel level = LogLevel::info) {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%L%$] %v");

        logger_ = std::make_shared<spdlog::logger>("license-manager", console_sink);
        logger_->set_level(convert_level(level));
        logger_->flush_on(spdlog::level::warn);
    }

    void debug(const std::string& message) override {
        logger_->debug(message);
    }

    void info(const std::string& message) override {
        logger_->info(message);
    }

    void warn(const std::string& message) override {
        logger_->warn(message);
    }

    void error(const std::string& message) override {
        logger_->error(message);
    }

    void debugf(const char* format, ...) override {
        char buf[1024];
        va_list args;
        va_start(args, format);
        vsnprintf(buf, sizeof(buf), format, args);
        va_end(args);
        logger_->log(spdlog::level::debug, std::string(buf));
    }

    void infof(const char* format, ...) override {
        char buf[1024];
        va_list args;
        va_start(args, format);
        vsnprintf(buf, sizeof(buf), format, args);
        va_end(args);
        logger_->log(spdlog::level::info, std::string(buf));
    }

    void warnf(const char* format, ...) override {
        char buf[1024];
        va_list args;
        va_start(args, format);
        vsnprintf(buf, sizeof(buf), format, args);
        va_end(args);
        logger_->log(spdlog::level::warn, std::string(buf));
    }

    void errorf(const char* format, ...) override {
        char buf[1024];
        va_list args;
        va_start(args, format);
        vsnprintf(buf, sizeof(buf), format, args);
        va_end(args);
        logger_->log(spdlog::level::err, std::string(buf));
    }

    std::shared_ptr<spdlog::logger> native_logger() { return logger_; }

private:
    static spdlog::level::level_enum convert_level(LogLevel level) {
        switch (level) {
            case LogLevel::debug: return spdlog::level::debug;
            case LogLevel::info:  return spdlog::level::info;
            case LogLevel::warn:  return spdlog::level::warn;
            case LogLevel::error: return spdlog::level::err;
            default:              return spdlog::level::info;
        }
    }

    std::shared_ptr<spdlog::logger> logger_;
};

inline LogLevel parse_log_level(const std::string& level) {
    if (level == "debug") return LogLevel::debug;
    if (level == "warn")  return LogLevel::warn;
    if (level == "error") return LogLevel::error;
    return LogLevel::info;
}

} // namespace license_manager

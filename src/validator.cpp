#include "validator.hpp"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>

using json = nlohmann::json;

namespace license_manager {

struct Validator::Impl {
    RSA* rsa_public_key = nullptr;

    Impl(const std::string& public_key_pem) {
        BIO* bio = BIO_new_mem_buf(public_key_pem.data(), static_cast<int>(public_key_pem.size()));
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }

        rsa_public_key = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
        if (!rsa_public_key) {
            // Try PEM_read_bio_PUBKEY
            BIO* bio2 = BIO_new_mem_buf(public_key_pem.data(), static_cast<int>(public_key_pem.size()));
            EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio2, nullptr, nullptr, nullptr);
            BIO_free(bio2);

            if (pkey) {
                rsa_public_key = EVP_PKEY_get1_RSA(pkey);
                EVP_PKEY_free(pkey);
            }
        }

        BIO_free(bio);

        if (!rsa_public_key) {
            throw std::runtime_error("Failed to parse RSA public key");
        }
    }

    ~Impl() {
        if (rsa_public_key) {
            RSA_free(rsa_public_key);
        }
    }
};

Validator::Validator(const std::string& public_key_pem)
    : pimpl_(std::make_unique<Impl>(public_key_pem)) {}

Validator::~Validator() = default;

static bool base64_decode(const std::string& encoded, std::vector<uint8_t>& decoded) {
    static const char* decode_table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    decoded.clear();
    int val = 0;
    int bits = -8;

    for (char c : encoded) {
        if (c == '=') break;
        if (c == ' ' || c == '\n' || c == '\r') continue;

        const char* p = std::strchr(decode_table, c);
        if (!p) return false;

        val = (val << 6) | (p - decode_table);
        bits += 6;

        if (bits >= 0) {
            decoded.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }

    return true;
}

std::pair<LicensePayload, std::error_code>
Validator::verify(const std::vector<uint8_t>& license_data, const std::string& expected_fingerprint) {
    if (license_data.empty()) {
        return {{}, make_error_code(Errc::validation_empty_license)};
    }

    // Find start of JSON (skip whitespace)
    size_t start = 0;
    while (start < license_data.size() &&
           (license_data[start] == ' ' || license_data[start] == '\n' ||
            license_data[start] == '\r' || license_data[start] == '\t')) {
        ++start;
    }

    // Check if it's already JSON or needs base64 decode
    std::vector<uint8_t> normalized_data;
    if (start < license_data.size() && license_data[start] == '{') {
        normalized_data = std::vector<uint8_t>(license_data.begin() + start, license_data.end());
    } else {
        // Try base64 decode
        std::string encoded(license_data.begin() + start, license_data.end());
        // Trim whitespace
        while (!encoded.empty() && std::isspace(encoded.back())) encoded.pop_back();

        if (!base64_decode(encoded, normalized_data)) {
            return {{}, make_error_code(Errc::validation_decode_error)};
        }
    }

    // Parse envelope
    std::string json_str(normalized_data.begin(), normalized_data.end());
    json envelope_json;
    try {
        envelope_json = json::parse(json_str);
    } catch (...) {
        return {{}, make_error_code(Errc::validation_parse_error)};
    }

    // Extract fields
    std::string algorithm = envelope_json.value("algorithm", "RSA-SHA256");
    std::string data_str = envelope_json.value("data", "");
    std::string signature_str = envelope_json.value("signature", "");

    if (data_str.empty() || signature_str.empty()) {
        return {{}, make_error_code(Errc::validation_decode_error)};
    }

    // Decode signature
    std::vector<uint8_t> signature;
    if (!base64_decode(signature_str, signature)) {
        return {{}, make_error_code(Errc::validation_decode_error)};
    }

    // Verify signature
    std::vector<uint8_t> data_bytes(data_str.begin(), data_str.end());
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data_bytes.data(), data_bytes.size(), hash.data());

    // Normalize algorithm name
    std::string algo_upper = algorithm;
    std::transform(algo_upper.begin(), algo_upper.end(), algo_upper.begin(), ::toupper);
    if (algo_upper.empty()) algo_upper = "RSA-SHA256";

    int verify_result = 0;
    if (algo_upper == "RSA-PSS-SHA256" || algo_upper == "RSA-PSS-SHA-256") {
        // For RSA-PSS, use PKCS1v15 as fallback (OpenSSL compatibility)
        verify_result = RSA_verify(
            NID_sha256,
            hash.data(),
            static_cast<unsigned int>(hash.size()),
            signature.data(),
            static_cast<unsigned int>(signature.size()),
            pimpl_->rsa_public_key
        );
    } else {
        // Default to PKCS1v15
        verify_result = RSA_verify(
            NID_sha256,
            hash.data(),
            static_cast<unsigned int>(hash.size()),
            signature.data(),
            static_cast<unsigned int>(signature.size()),
            pimpl_->rsa_public_key
        );
    }

    if (verify_result != 1) {
        return {{}, make_error_code(Errc::validation_signature_mismatch)};
    }

    // Parse payload
    LicensePayload payload;
    try {
        json payload_json = json::parse(data_str);

        payload.license_key = payload_json.value("license_key", "");
        payload.authorization_code = payload_json.value("authorization_code", "");
        payload.authorization_code_id = payload_json.value("authorization_code_id", "");
        payload.hardware_fingerprint = payload_json.value("hardware_fingerprint", "");
        payload.status = payload_json.value("status", "");
        payload.deployment_type = payload_json.value("deployment_type", "");
        payload.max_activations = payload_json.value("max_activations", 0);

        // Parse dates
        auto parse_time = [](const json& j) -> std::chrono::system_clock::time_point {
            if (j.is_string()) {
                std::string s = j.get<std::string>();
                std::tm tm = {};
                std::istringstream ss(s);
                ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
                if (ss.fail()) {
                    ss.clear();
                    ss.str(s);
                    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
                }
                return std::chrono::system_clock::from_time_t(std::mktime(&tm));
            }
            return {};
        };

        if (payload_json.contains("end_date")) {
            payload.end_date = parse_time(payload_json["end_date"]);
            payload.expires_at = payload.end_date;
        }
        if (payload_json.contains("start_date")) {
            payload.start_date = parse_time(payload_json["start_date"]);
        }
        if (payload_json.contains("activated_at") && !payload_json["activated_at"].is_null()) {
            payload.activated_at = parse_time(payload_json["activated_at"]);
        }
        if (payload_json.contains("generated_at") && !payload_json["generated_at"].is_null()) {
            payload.generated_at = parse_time(payload_json["generated_at"]);
        }

        // Store extras
        for (auto& [key, value] : payload_json.items()) {
            if (key != "license_key" && key != "authorization_code" &&
                key != "authorization_code_id" && key != "hardware_fingerprint" &&
                key != "status" && key != "deployment_type" &&
                key != "max_activations" && key != "end_date" &&
                key != "start_date" && key != "activated_at" &&
                key != "generated_at") {
                payload.extras[key] = value;
            }
        }

    } catch (...) {
        return {{}, make_error_code(Errc::validation_parse_error)};
    }

    // Check fingerprint if provided
    if (!expected_fingerprint.empty() && !payload.hardware_fingerprint.empty()) {
        if (payload.hardware_fingerprint != expected_fingerprint) {
            return {{}, make_error_code(Errc::validation_fingerprint_mismatch)};
        }
    }

    // Check expiration
    if (payload.expires_at != std::chrono::system_clock::time_point{}) {
        auto now = std::chrono::system_clock::now();
        if (now > payload.expires_at) {
            return {{}, make_error_code(Errc::validation_expired)};
        }
    }

    return {payload, {}};
}

std::pair<LicensePayload, std::error_code>
Validator::verify_base64(const std::string& base64_license, const std::string& expected_fingerprint) {
    std::vector<uint8_t> decoded;
    if (!base64_decode(base64_license, decoded)) {
        return {{}, make_error_code(Errc::validation_decode_error)};
    }
    return verify(decoded, expected_fingerprint);
}

} // namespace license_manager

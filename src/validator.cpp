#include "validator.hpp"
#include <openssl/rsa.h>
#include <openssl/bn.h>
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
#include <cstdlib>

using json = nlohmann::json;

namespace license_manager {

struct Validator::Impl {
    EVP_PKEY* pkey = nullptr;

    Impl(const std::string& public_key_pem) {
        BIO* bio = BIO_new_mem_buf(public_key_pem.data(), static_cast<int>(public_key_pem.size()));
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }
        pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) {
            throw std::runtime_error("Failed to parse RSA public key");
        }
    }

    ~Impl() {
        if (pkey) {
            EVP_PKEY_free(pkey);
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

// Manual RSA-PSS verification with variable salt length
// This works correctly with OpenSSL 3.x where EVP API may have issues
static bool verify_rsa_pss_sha256(EVP_PKEY* pkey,
                                  const std::vector<uint8_t>& data,
                                  const std::vector<uint8_t>& signature) {
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) return false;
    int mod_bytes = RSA_size(rsa);
    int key_bits = RSA_bits(rsa);
    RSA_free(rsa);

    fprintf(stderr, "[PSS] mod_bytes=%d key_bits=%d sig_len=%zu\n",
            mod_bytes, key_bits, signature.size());
    if ((int)signature.size() != mod_bytes) return false;

    unsigned char* em = (unsigned char*)malloc(mod_bytes);
    if (!em) return false;

    // Decrypt signature -> EM
    RSA* rsa_key = EVP_PKEY_get1_RSA(pkey);
    if (!rsa_key) { free(em); return false; }
    int em_len = RSA_public_decrypt(
        static_cast<int>(signature.size()), signature.data(),
        em, rsa_key, RSA_NO_PADDING);
    RSA_free(rsa_key);
    fprintf(stderr, "[PSS] RSA_NO_PADDING decrypt: em_len=%d\n", em_len);
    if (em_len <= 0) { free(em); return false; }

    // Print first 16 bytes of EM
    fprintf(stderr, "[PSS] EM first 16: ");
    for (int i = 0; i < 16 && i < em_len; i++) fprintf(stderr, "%02x ", em[i]);
    fprintf(stderr, "\n");

    // ─── Method 1: OpenSSL EVP_DigestVerify (auto salt) ───
    {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX* pctx = nullptr;
        int ok = EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), nullptr, pkey);
        if (ok == 1) {
            // RSA_PSS_SALTLEN_AUTO = -2, lets OpenSSL auto-detect
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_AUTO);
            ok = EVP_DigestVerifyUpdate(ctx, data.data(), data.size());
            if (ok == 1) {
                ok = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
                fprintf(stderr, "[PSS] EVP auto: %s\n", ok == 1 ? "OK" : "FAIL");
                if (ok == 1) { EVP_MD_CTX_free(ctx); free(em); return true; }
            } else { fprintf(stderr, "[PSS] EVP update failed\n"); }
        }
        EVP_MD_CTX_free(ctx);
    }

    // ─── Method 2: OpenSSL EVP with max salt ───
    {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX* pctx = nullptr;
        int ok = EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), nullptr, pkey);
        if (ok == 1) {
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_MAX);
            ok = EVP_DigestVerifyUpdate(ctx, data.data(), data.size());
            if (ok == 1) {
                ok = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
                fprintf(stderr, "[PSS] EVP max salt: %s\n", ok == 1 ? "OK" : "FAIL");
                if (ok == 1) { EVP_MD_CTX_free(ctx); free(em); return true; }
            }
        }
        EVP_MD_CTX_free(ctx);
    }

    // ─── Method 3: Try different fixed salt lengths (32, 20, emLen-hashLen-2) ───
    const int try_salts[] = { SHA256_DIGEST_LENGTH, 20, mod_bytes - SHA256_DIGEST_LENGTH - 2, 16 };
    for (int si = 0; si < 4; si++) {
        int salt_len = try_salts[si];
        if (salt_len < 0 || salt_len > mod_bytes) continue;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX* pctx = nullptr;
        int ok = EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), nullptr, pkey);
        if (ok == 1) {
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_len);
            ok = EVP_DigestVerifyUpdate(ctx, data.data(), data.size());
            if (ok == 1) {
                ok = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
                fprintf(stderr, "[PSS] EVP salt=%d: %s\n", salt_len, ok == 1 ? "OK" : "FAIL");
                if (ok == 1) { EVP_MD_CTX_free(ctx); free(em); return true; }
            }
        }
        EVP_MD_CTX_free(ctx);
    }

    // ─── Method 4: Manual PSS verification (em_len must have 0x00 0x01 at start) ───
    if (em[0] == 0x00 && em[1] == 0x01) {
        size_t ps_start = 2;
        while (ps_start < (size_t)em_len && em[ps_start] == 0xFF) ++ps_start;
        if (ps_start < (size_t)em_len && em[ps_start] == 0x00) {
            size_t t_start = ps_start + 1;
            unsigned char der_sha256[] = {
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
            };
            if (t_start + sizeof(der_sha256) + SHA256_DIGEST_LENGTH <= (size_t)em_len) {
                bool der_ok = true;
                for (size_t i = 0; i < sizeof(der_sha256); i++) {
                    if (em[t_start + i] != der_sha256[i]) { der_ok = false; break; }
                }
                if (der_ok) {
                    const unsigned char* embedded_hash = em + t_start + sizeof(der_sha256);
                    size_t salt_start = t_start + sizeof(der_sha256) + SHA256_DIGEST_LENGTH;
                    size_t salt_len = em_len - salt_start;
                    fprintf(stderr, "[PSS] Manual: found PSS EM, salt_len=%zu\n", salt_len);

                    unsigned char mp[8 + SHA256_DIGEST_LENGTH + 256];
                    memset(mp, 0, 8);
                    unsigned char data_hash[SHA256_DIGEST_LENGTH];
                    SHA256(data.data(), data.size(), data_hash);
                    memcpy(mp + 8, data_hash, SHA256_DIGEST_LENGTH);
                    memcpy(mp + 8 + SHA256_DIGEST_LENGTH, em + salt_start, salt_len);
                    unsigned char computed_hash[SHA256_DIGEST_LENGTH];
                    SHA256(mp, 8 + SHA256_DIGEST_LENGTH + salt_len, computed_hash);

                    bool match = memcmp(computed_hash, embedded_hash, SHA256_DIGEST_LENGTH) == 0;
                    fprintf(stderr, "[PSS] Manual verify: %s\n", match ? "OK" : "FAIL");
                    if (match) { free(em); return true; }
                }
            }
        }
    }

    free(em);
    return false;
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
    fprintf(stderr, "[VERIFY] sig_b64: %.*s\n", 40, signature_str.c_str());
    if (!base64_decode(signature_str, signature)) {
        return {{}, make_error_code(Errc::validation_decode_error)};
    }

    std::vector<uint8_t> data_bytes(data_str.begin(), data_str.end());
    unsigned char data_hash[SHA256_DIGEST_LENGTH];
    SHA256(data_bytes.data(), data_bytes.size(), data_hash);
    fprintf(stderr, "[VERIFY] data_str len=%zu, SHA256(data): ", data_str.size());
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) fprintf(stderr, "%02x", data_hash[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "[VERIFY] sig_b64 first 40: %.*s\n", 40, signature_str.c_str());

    // Normalize algorithm name
    std::string algo_upper = algorithm;
    std::transform(algo_upper.begin(), algo_upper.end(), algo_upper.begin(), ::toupper);
    if (algo_upper.empty()) algo_upper = "RSA-SHA256";

    bool verified = false;

    if (algo_upper == "RSA-PSS-SHA256" || algo_upper == "RSA-PSS-SHA-256") {
        verified = verify_rsa_pss_sha256(pimpl_->pkey, data_bytes, signature);
    } else {
        // PKCS1v15
        RSA* rsa = EVP_PKEY_get1_RSA(pimpl_->pkey);
        if (rsa) {
            unsigned char der_buf[512];
            int der_len = RSA_public_decrypt(
                static_cast<int>(signature.size()), signature.data(),
                der_buf, rsa, RSA_PKCS1_PADDING);
            RSA_free(rsa);
            if (der_len >= SHA256_DIGEST_LENGTH) {
                // The last SHA256_DIGEST_LENGTH bytes should be the hash
                unsigned char our_hash[SHA256_DIGEST_LENGTH];
                SHA256(data_bytes.data(), data_bytes.size(), our_hash);
                if (memcmp(der_buf + der_len - SHA256_DIGEST_LENGTH, our_hash, SHA256_DIGEST_LENGTH) == 0) {
                    verified = true;
                }
            }
        }
    }

    if (!verified) {
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
                if (!value.is_null()) {
                    payload.extras[key] = value;
                }
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

void Validator::set_public_key(const std::string& public_key_pem) {
    BIO* bio = BIO_new_mem_buf(public_key_pem.data(), static_cast<int>(public_key_pem.size()));
    if (!bio) return;
    EVP_PKEY* new_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (new_key) {
        if (pimpl_->pkey) {
            EVP_PKEY_free(pimpl_->pkey);
        }
        pimpl_->pkey = new_key;
    }
}

} // namespace license_manager

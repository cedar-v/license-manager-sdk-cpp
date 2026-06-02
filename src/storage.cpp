#include "storage.hpp"
#include <cstdio>
#include <algorithm>
#include <cstring>
#include <errno.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

namespace license_manager {

static constexpr size_t AES_KEY_SIZE = 32;  // 256-bit
static constexpr size_t AES_BLK_SIZE = 16;
static constexpr const char* ENCRYPTED_PREFIX = "enc:";

FileStorage::FileStorage(std::string path, std::vector<uint8_t> secret)
    : path_(std::move(path)), secret_(std::move(secret)) {}

FileStorage::FileStorage(std::string path, std::span<const uint8_t> secret)
    : path_(std::move(path)), secret_(secret.begin(), secret.end()) {}

std::error_code FileStorage::save(std::span<const uint8_t> data) {
    std::vector<uint8_t> processed = maybe_encrypt(data);
    return write_atomic(path_, processed);
}

std::pair<std::vector<uint8_t>, std::error_code> FileStorage::load() {
    FILE* fp = fopen(path_.c_str(), "rb");
    if (!fp) {
        if (errno == ENOENT) {
            return {{}, make_error_code(Errc::storage_file_not_found)};
        }
        return {{}, make_error_code(Errc::storage_read_error)};
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    std::vector<uint8_t> content(static_cast<size_t>(size));
    size_t read_bytes = fread(content.data(), 1, static_cast<size_t>(size), fp);
    fclose(fp);

    if (read_bytes != static_cast<size_t>(size)) {
        return {{}, make_error_code(Errc::storage_read_error)};
    }

    auto decrypted = maybe_decrypt(content);
    if (!decrypted.has_value()) {
        return {{}, make_error_code(Errc::storage_decrypt_error)};
    }

    return {std::move(*decrypted), {}};
}

std::error_code FileStorage::remove() {
    if (std::remove(path_.c_str()) != 0 && errno != ENOENT) {
        return make_error_code(Errc::storage_write_error);
    }
    return {};
}

std::vector<uint8_t> FileStorage::maybe_encrypt(std::span<const uint8_t> data) const {
    if (secret_.empty()) {
        return {data.begin(), data.end()};
    }

    // Generate random IV
    uint8_t iv[AES_BLK_SIZE];
    if (RAND_bytes(iv, AES_BLK_SIZE) != 1) {
        return {data.begin(), data.end()};  // Fallback to unencrypted
    }

    // Derive key from secret
    uint8_t key[AES_KEY_SIZE];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, secret_.data(), secret_.size());
    unsigned int key_len = AES_KEY_SIZE;
    EVP_DigestFinal_ex(ctx, key, &key_len);
    EVP_MD_CTX_free(ctx);

    // Encrypt using AES-256-GCM
    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);  // No padding needed for GCM

    std::vector<uint8_t> ciphertext(data.size());
    int out_len = 0;

    if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return {data.begin(), data.end()};
    }

    EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, AES_BLK_SIZE, nullptr);
    EVP_EncryptInit_ex(cipher_ctx, nullptr, nullptr, key, iv);

    int enc_len = 0;
    EVP_EncryptUpdate(cipher_ctx, nullptr, &enc_len, data.data(), static_cast<int>(data.size()));
    EVP_EncryptFinal_ex(cipher_ctx, ciphertext.data() + enc_len, &out_len);
    enc_len += out_len;

    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(cipher_ctx);

    // Format: "enc:" + iv + tag + ciphertext
    std::vector<uint8_t> result;
    result.reserve(4 + AES_BLK_SIZE + 16 + enc_len);
    result.insert(result.end(), ENCRYPTED_PREFIX, ENCRYPTED_PREFIX + 4);
    result.insert(result.end(), iv, iv + AES_BLK_SIZE);
    result.insert(result.end(), tag, tag + 16);
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + enc_len);

    return result;
}

std::optional<std::vector<uint8_t>> FileStorage::maybe_decrypt(std::span<const uint8_t> data) const {
    if (secret_.empty() || data.size() < 4) {
        return {{data.begin(), data.end()}};
    }

    // Check for encrypted prefix
    if (std::string(reinterpret_cast<const char*>(data.data()), 4) != ENCRYPTED_PREFIX) {
        return {{data.begin(), data.end()}};  // Not encrypted, return as-is
    }

    if (data.size() < 4 + AES_BLK_SIZE + 16) {
        return std::nullopt;  // Too short
    }

    size_t offset = 4;
    uint8_t iv[AES_BLK_SIZE];
    std::copy(data.begin() + offset, data.begin() + offset + AES_BLK_SIZE, iv);
    offset += AES_BLK_SIZE;

    uint8_t tag[16];
    std::copy(data.begin() + offset, data.begin() + offset + 16, tag);
    offset += 16;

    auto ciphertext = std::vector<uint8_t>(data.begin() + offset, data.end());

    // Derive key from secret
    uint8_t key[AES_KEY_SIZE];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, secret_.data(), secret_.size());
    unsigned int key_len = AES_KEY_SIZE;
    EVP_DigestFinal_ex(ctx, key, &key_len);
    EVP_MD_CTX_free(ctx);

    // Decrypt using AES-256-GCM
    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);

    std::vector<uint8_t> plaintext(ciphertext.size());
    int out_len = 0;

    if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return std::nullopt;
    }

    EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, AES_BLK_SIZE, nullptr);
    EVP_DecryptInit_ex(cipher_ctx, nullptr, nullptr, key, iv);
    EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

    if (EVP_DecryptUpdate(cipher_ctx, nullptr, &out_len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return std::nullopt;
    }

    int dec_len = out_len;
    int final_len = 0;
    if (EVP_DecryptFinal_ex(cipher_ctx, plaintext.data() + dec_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        return std::nullopt;  // Tag verification failed
    }
    dec_len += final_len;

    EVP_CIPHER_CTX_free(cipher_ctx);
    plaintext.resize(static_cast<size_t>(dec_len));

    return plaintext;
}

std::error_code FileStorage::write_atomic(const std::string& path, std::span<const uint8_t> data) {
    std::string file_path = path;
    // Recursively create directories if needed
    std::string dir;
    size_t pos = path.find_last_of("/\\");
    if (pos != std::string::npos) {
        dir = path.substr(0, pos);
    } else {
        dir = ".";
    }

    if (!dir.empty() && dir != ".") {
        // Build path component by component
        size_t last_sep = 0;
        for (size_t i = 0; i <= dir.size(); ++i) {
            if (i == dir.size() || dir[i] == '/' || dir[i] == '\\') {
                if (i > last_sep) {
                    std::string part = dir.substr(0, i);
#ifdef _WIN32
                    BOOL r = ::CreateDirectoryA(part.c_str(), nullptr);
                    (void)r; // Ignore "already exists" error
#else
                    mkdir(part.c_str(), 0755);
#endif
                }
                last_sep = i + 1;
            }
        }
    }

    std::string tmp_path = file_path + ".tmp";
    FILE* fp = fopen(tmp_path.c_str(), "wb");
    if (!fp) {
        fprintf(stderr, "[STORAGE] fopen failed: errno=%d strerror=%s\n", errno, strerror(errno));
        return make_error_code(Errc::storage_write_error);
    }

    size_t written = fwrite(data.data(), 1, data.size(), fp);
    fclose(fp);

    if (written != data.size()) {
        std::remove(tmp_path.c_str());
        return make_error_code(Errc::storage_write_error);
    }

    // Atomic rename: try std::rename first, fall back to CopyFile+Delete
    if (std::rename(tmp_path.c_str(), file_path.c_str()) != 0) {
        // Windows: std::rename fails with EEXIST when dest has different type
        // Use CopyFile + Delete as fallback
#ifdef _WIN32
        if (!CopyFileA(tmp_path.c_str(), file_path.c_str(), FALSE)) {
            std::remove(tmp_path.c_str());
            return make_error_code(Errc::storage_write_error);
        }
        DeleteFileA(tmp_path.c_str());
#else
        std::remove(tmp_path.c_str());
        return make_error_code(Errc::storage_write_error);
#endif
    }

    return {};
}

} // namespace license_manager

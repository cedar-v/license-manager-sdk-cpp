// Test PSS verification using the EXACT same approach as C++ validator
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

// Exactly like C++ validator
static int base64_decode(const char* encoded, unsigned char* out, int max_len) {
    static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0, bits = -8, pos = 0;
    for (int i = 0; encoded[i]; i++) {
        char c = encoded[i];
        if (c == '=') break;
        if (c == ' ' || c == '\n' || c == '\r') continue;
        const char* p = strchr(table, c);
        if (!p) return -1;
        val = (val << 6) | (p - table);
        bits += 6;
        if (bits >= 0 && pos < max_len) {
            out[pos++] = (val >> bits) & 0xFF;
            bits -= 8;
        }
    }
    return pos;
}

// Copy of C++ validator's verify_rsa_pss_sha256
static int verify_rsa_pss_sha256(EVP_PKEY* pkey, const unsigned char* data, size_t data_len,
                                  const unsigned char* sig, size_t sig_len) {
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) return 0;

    int mod_bytes = RSA_size(rsa);
    if ((int)sig_len != mod_bytes) { RSA_free(rsa); return 0; }

    unsigned char* em = (unsigned char*)malloc(mod_bytes);
    int em_len = RSA_public_decrypt((int)sig_len, sig, em, rsa, RSA_NO_PADDING);
    RSA_free(rsa);

    if (em_len != mod_bytes || em_len < 2) { free(em); return 0; }

    if (em[0] != 0x00 || em[1] != 0x01) { free(em); return 0; }

    size_t ps_start = 2;
    while (ps_start < (size_t)em_len && em[ps_start] == 0xFF) ++ps_start;
    if (ps_start >= (size_t)em_len || em[ps_start] != 0x00) { free(em); return 0; }
    size_t t_start = ps_start + 1;

    unsigned char der_sha256[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    };
    size_t der_len = sizeof(der_sha256);
    if (t_start + der_len + SHA256_DIGEST_LENGTH > (size_t)em_len) { free(em); return 0; }

    for (size_t i = 0; i < der_len; i++)
        if (em[t_start + i] != der_sha256[i]) { free(em); return 0; }

    const unsigned char* embedded_hash = em + t_start + der_len;
    size_t salt_start = t_start + der_len + SHA256_DIGEST_LENGTH;
    size_t salt_len = em_len - salt_start;
    const unsigned char* salt = em + salt_start;

    unsigned char mp[8 + SHA256_DIGEST_LENGTH + 256];
    memset(mp, 0, 8);
    unsigned char data_hash[SHA256_DIGEST_LENGTH];
    SHA256(data, data_len, data_hash);
    memcpy(mp + 8, data_hash, SHA256_DIGEST_LENGTH);
    memcpy(mp + 8 + SHA256_DIGEST_LENGTH, salt, salt_len);

    unsigned char computed_hash[SHA256_DIGEST_LENGTH];
    SHA256(mp, 8 + SHA256_DIGEST_LENGTH + salt_len, computed_hash);

    int result = memcmp(computed_hash, embedded_hash, SHA256_DIGEST_LENGTH) == 0;
    free(em);
    return result;
}

int main() {
    // Generate a test key pair
    RSA* rsa = RSA_generate_key_ex(2048, 65537, NULL);
    if (!rsa) { printf("RSA_generate_key_ex failed\n"); return 1; }

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    // Test data
    const char* data_str = "Hello, World!";
    unsigned char data_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data_str, strlen(data_str), data_hash);

    // Sign with OpenSSL's RSA_sign (PKCS1v15)
    unsigned char sig[512];
    unsigned int sig_len = 0;
    int ok = RSA_sign(NID_sha256, data_hash, SHA256_DIGEST_LENGTH, sig, &sig_len, rsa);
    printf("RSA_sign (PKCS1v15) result: %d, sig_len=%u\n", ok, sig_len);

    // Verify with our PSS verifier (should fail - PKCS1v15 != PSS)
    int v1 = verify_rsa_pss_sha256(pkey, (unsigned char*)data_str, strlen(data_str), sig, sig_len);
    printf("Verify PKCS1v15 with PSS verifier: %d (expected 0)\n", v1);

    // Now test with PSS using OpenSSL's EVP API
    unsigned char sig_pss[512];
    unsigned int sig_pss_len = 0;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkey_ctx = NULL;

    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha256(), NULL, pkey);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_MAX_SIGN);
    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256());

    size_t len = 0;
    EVP_DigestSign(md_ctx, NULL, &len, (unsigned char*)data_str, strlen(data_str));
    if (len < sizeof(sig_pss)) {
        EVP_DigestSign(md_ctx, sig_pss, &len, (unsigned char*)data_str, strlen(data_str));
        printf("PSS signature generated, len=%zu\n", len);

        // Verify with OpenSSL EVP
        EVP_MD_CTX* vctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(vctx, EVP_sha256(), NULL);
        EVP_PKEY_CTX* vpkey_ctx = NULL;
        EVP_DigestVerifyInit(vctx, &vpkey_ctx, EVP_sha256(), NULL, pkey);
        EVP_PKEY_CTX_set_rsa_padding(vpkey_ctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(vpkey_ctx, RSA_PSS_SALTLEN_MAX_SIGN);
        EVP_PKEY_CTX_set_rsa_mgf1_md(vpkey_ctx, EVP_sha256());

        int v_ok = EVP_DigestVerify(vctx, sig_pss, len, (unsigned char*)data_str, strlen(data_str));
        printf("OpenSSL EVP PSS verify: %d (expected 1)\n", v_ok);

        // Verify with our manual PSS verifier
        int v2 = verify_rsa_pss_sha256(pkey, (unsigned char*)data_str, strlen(data_str), sig_pss, len);
        printf("Our manual PSS verify: %d (expected 1)\n", v2);

        EVP_MD_CTX_free(vctx);
    }
    EVP_MD_CTX_free(md_ctx);

    EVP_PKEY_free(pkey);
    return 0;
}

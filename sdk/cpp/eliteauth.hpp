#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

namespace EliteAuth {

inline constexpr const char* SIGNING_PUBLIC_KEY = "Yo7wBxsz8mCN6LX89Ja0H3pNlcLXJHrJ50u5BtZuakQ";
inline constexpr const char* SIGNING_KEY_ID = "eliteauth-ed25519-2026-01";

struct Result {
    bool success = false;
    bool valid = false;
    std::string error;
    nlohmann::json data;
    long http_status = 0;
    std::string request_id;
};

class Client {
public:
    Client(std::string api_url, std::string app_id, std::string version, std::string integrity_sha256 = {})
        : api_url_(trim_slash(std::move(api_url))), app_id_(std::move(app_id)), version_(std::move(version)), integrity_sha256_(normalize_hash(std::move(integrity_sha256))) {
        if (api_url_.empty() || app_id_.empty() || version_.empty()) throw std::invalid_argument("api_url, app_id and version are required");
        if (sodium_init() < 0) throw std::runtime_error("libsodium initialization failed");
        public_key_ = decode_base64url(SIGNING_PUBLIC_KEY);
        if (public_key_.size() != crypto_sign_PUBLICKEYBYTES) throw std::runtime_error("invalid pinned EliteAuth public key");
    }

    Result activate(const std::string& license_key, const std::string& hwid) {
        const auto nonce = random_base64url(24);
        nlohmann::json body = {
            {"app_id", app_id_},
            {"license_key", license_key},
            {"hwid", hwid},
            {"version", version_},
            {"sdk_version", "cpp-1.1.0"},
            {"integrity_sha256", integrity_sha256_.empty() ? nlohmann::json(nullptr) : nlohmann::json(integrity_sha256_)},
            {"timestamp", unix_time()},
            {"nonce", nonce}
        };
        auto result = post_signed("/v1/license/activate", body, nonce);
        if (result.success) {
            session_token_ = result.data.at("session").at("token").get<std::string>();
            challenge_ = result.data.at("session").at("challenge").get<std::string>();
            if (session_token_.empty() || challenge_.empty()) throw std::runtime_error("signed activation response is missing session state");
        }
        return result;
    }

    Result check_session(const std::string& hwid) {
        if (session_token_.empty() || challenge_.empty()) throw std::runtime_error("call activate before check_session");
        const auto nonce = random_base64url(24);
        nlohmann::json body = {
            {"app_id", app_id_},
            {"session_token", session_token_},
            {"challenge", challenge_},
            {"hwid", hwid},
            {"sdk_version", "cpp-1.1.0"},
            {"integrity_sha256", integrity_sha256_.empty() ? nlohmann::json(nullptr) : nlohmann::json(integrity_sha256_)},
            {"timestamp", unix_time()},
            {"nonce", nonce}
        };
        auto result = post_signed("/v1/session/check", body, nonce);
        if (result.success && result.valid) {
            challenge_ = result.data.at("session").at("challenge").get<std::string>();
            if (challenge_.empty()) throw std::runtime_error("signed session response did not rotate the challenge");
        }
        return result;
    }

    void clear_session() {
        session_token_.clear();
        challenge_.clear();
    }

    static std::string sha256_file(const std::string& path) {
        std::ifstream input(path, std::ios::binary);
        if (!input) throw std::runtime_error("unable to open file for hashing");
        crypto_hash_sha256_state state;
        crypto_hash_sha256_init(&state);
        std::array<unsigned char, 1024 * 1024> buffer{};
        while (input) {
            input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
            const auto count = input.gcount();
            if (count > 0) crypto_hash_sha256_update(&state, buffer.data(), static_cast<unsigned long long>(count));
        }
        std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
        crypto_hash_sha256_final(&state, digest.data());
        std::ostringstream out;
        for (auto byte : digest) out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        return out.str();
    }

private:
    std::string api_url_;
    std::string app_id_;
    std::string version_;
    std::string integrity_sha256_;
    std::vector<unsigned char> public_key_;
    std::string session_token_;
    std::string challenge_;

    Result post_signed(const std::string& path, const nlohmann::json& body, const std::string& expected_nonce) {
        CURL* curl = curl_easy_init();
        if (!curl) throw std::runtime_error("curl initialization failed");
        std::string response_body;
        const auto request_body = body.dump();
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Cache-Control: no-store");
        curl_easy_setopt(curl, CURLOPT_URL, (api_url_ + path).c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request_body.size()));
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
        const auto code = curl_easy_perform(curl);
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        if (code != CURLE_OK) throw std::runtime_error(curl_easy_strerror(code));

        const auto payload = verify_envelope(nlohmann::json::parse(response_body), expected_nonce);
        const auto data = payload.at("data");
        Result result;
        result.success = data.value("success", false);
        result.valid = data.value("valid", false);
        result.error = data.value("error", "");
        result.data = data;
        result.http_status = status;
        result.request_id = payload.value("request_id", "");
        return result;
    }

    nlohmann::json verify_envelope(const nlohmann::json& envelope, const std::string& expected_nonce) const {
        if (envelope.value("key_id", "") != SIGNING_KEY_ID || envelope.value("algorithm", "") != "Ed25519") throw std::runtime_error("unexpected EliteAuth signing key or algorithm");
        const auto payload_bytes = decode_base64url(envelope.at("payload").get<std::string>());
        const auto signature = decode_base64url(envelope.at("signature").get<std::string>());
        if (signature.size() != crypto_sign_BYTES || crypto_sign_verify_detached(signature.data(), payload_bytes.data(), payload_bytes.size(), public_key_.data()) != 0) {
            throw std::runtime_error("EliteAuth response signature verification failed");
        }
        const auto payload = nlohmann::json::parse(payload_bytes.begin(), payload_bytes.end());
        if (payload.value("protocol", "") != "eliteauth-signed-v1") throw std::runtime_error("unsupported EliteAuth signed-response protocol");
        if (payload.value("nonce", "") != expected_nonce) throw std::runtime_error("EliteAuth response nonce mismatch");
        const auto server_time = payload.value("server_time", std::int64_t{0});
        if (std::llabs(unix_time() - server_time) > 300) throw std::runtime_error("EliteAuth response timestamp is outside the allowed window");
        return payload;
    }

    static size_t write_callback(char* data, size_t size, size_t count, void* output) {
        auto* text = static_cast<std::string*>(output);
        text->append(data, size * count);
        return size * count;
    }

    static std::int64_t unix_time() {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static std::string random_base64url(std::size_t byte_count) {
        std::vector<unsigned char> bytes(byte_count);
        randombytes_buf(bytes.data(), bytes.size());
        std::string output(sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
        sodium_bin2base64(output.data(), output.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        output.resize(std::char_traits<char>::length(output.c_str()));
        return output;
    }

    static std::vector<unsigned char> decode_base64url(const std::string& value) {
        std::vector<unsigned char> output(value.size());
        std::size_t decoded = 0;
        if (sodium_base642bin(output.data(), output.size(), value.c_str(), value.size(), nullptr, &decoded, nullptr, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
            throw std::runtime_error("invalid base64url data");
        }
        output.resize(decoded);
        return output;
    }

    static std::string normalize_hash(std::string value) {
        for (auto& ch : value) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (!value.empty()) {
            if (value.size() != 64) throw std::invalid_argument("integrity_sha256 must be a 64-character SHA-256 value");
            for (char ch : value) if (!std::isxdigit(static_cast<unsigned char>(ch))) throw std::invalid_argument("integrity_sha256 must be hexadecimal");
        }
        return value;
    }

    static std::string trim_slash(std::string value) {
        while (!value.empty() && value.back() == '/') value.pop_back();
        return value;
    }
};

} // namespace EliteAuth

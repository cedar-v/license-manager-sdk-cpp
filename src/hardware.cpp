#include "hardware.hpp"
#include <openssl/sha.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <map>
#include <algorithm>

#ifdef _WIN32
    #include <windows.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "iphlpapi.lib")
    #include <intrin.h>
#elif defined(__APPLE__)
    #include <sys/utsname.h>
    #include <sys/types.h>
    #include <sys/sysctl.h>
    #include <ifaddrs.h>
    #include <net/if.h>
#else
    #include <unistd.h>
    #include <sys/utsname.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <ifaddrs.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <cstring>
#endif

namespace license_manager {

DefaultHardwareProvider::DefaultHardwareProvider(std::vector<std::string> fields)
    : fields_(std::move(fields)) {
    if (fields_.empty()) {
        fields_ = {"mac", "hostname"};
    }
    // Normalize to lowercase
    for (auto& f : fields_) {
        std::transform(f.begin(), f.end(), f.begin(), ::tolower);
    }
}

std::tuple<std::string, std::map<std::string, std::string>, std::error_code>
DefaultHardwareProvider::fingerprint() {
    std::map<std::string, std::string> data;

    for (const auto& field : fields_) {
        if (field == "hostname") {
            std::string hostname = get_hostname();
            if (!hostname.empty()) {
                data["hostname"] = hostname;
            }
        } else if (field == "mac") {
            std::string mac = get_mac_address();
            if (!mac.empty()) {
                data["mac"] = mac;
            }
        } else if (field == "cpu") {
            std::string cpu = get_cpu_info();
            if (!cpu.empty()) {
                data["cpu"] = cpu;
            }
        } else if (field == "memory") {
            std::string memory = get_memory_info();
            if (!memory.empty()) {
                data["memory"] = memory;
            }
        }
    }

    // Build deterministic string
    std::ostringstream oss;
    std::vector<std::string> keys;
    for (const auto& kv : data) {
        keys.push_back(kv.first);
    }
    std::sort(keys.begin(), keys.end());

    for (const auto& key : keys) {
        oss << key << "=" << data[key] << ";";
    }

    std::string input = oss.str();
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const uint8_t*>(input.data()), input.size(), hash.data());

    std::ostringstream hex;
    for (uint8_t b : hash) {
        hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }

    return {hex.str(), data, {}};
}

std::string DefaultHardwareProvider::get_hostname() const {
#ifdef _WIN32
    char hostname[256];
    DWORD size = sizeof(hostname);
    if (GetComputerNameExA(ComputerNameDnsHostname, hostname, &size)) {
        return std::string(hostname);
    }
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
#else
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
#endif
    return {};
}

std::string DefaultHardwareProvider::get_mac_address() const {
    std::string mac;

#ifdef _WIN32
    PIP_ADAPTER_INFO pAdapterInfo = nullptr;
    ULONG dwBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
    if (!pAdapterInfo) return {};

    DWORD dwResult = GetAdaptersInfo(pAdapterInfo, &dwBufLen);
    if (dwResult == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
        dwResult = GetAdaptersInfo(pAdapterInfo, &dwBufLen);
    }

    if (dwResult == ERROR_SUCCESS && pAdapterInfo) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (pAdapter->Type == MIB_IF_TYPE_ETHERNET && pAdapter->AddressLength == 6) {
                std::ostringstream oss;
                for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                    if (i > 0) oss << ":";
                    oss << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapter->Address[i];
                }
                mac = oss.str();
                std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
                break;
            }
            pAdapter = pAdapter->Next;
        }
    }
    if (pAdapterInfo) free(pAdapterInfo);

#elif defined(__APPLE__)
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK) {
                struct ifreq ifr;
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
                mac = ifa->ifa_name;  // Use interface name as fallback
                break;
            }
        }
        freeifaddrs(ifaddr);
    }

    // Try sysctl for actual MAC
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!(ifa->ifa_flags & IFF_LOOPBACK) && ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl* sdl = (struct sockaddr_dl*)ifa->ifa_addr;
                if (sdl->sdl_alen == 6) {
                    std::ostringstream oss;
                    unsigned char* mac_bytes = (unsigned char*)LLADDR(sdl);
                    for (int i = 0; i < 6; i++) {
                        if (i > 0) oss << ":";
                        oss << std::hex << std::setw(2) << std::setfill('0') << (int)mac_bytes[i];
                    }
                    mac = oss.str();
                    std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
                    break;
                }
            }
        }
        freeifaddrs(ifaddr);
    }

#else  // Linux
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!(ifa->ifa_flags & IFF_LOOPBACK) && ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
                struct ifreq ifr;
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
                int fd = socket(AF_INET, SOCK_DGRAM, 0);
                if (fd >= 0) {
                    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                        std::ostringstream oss;
                        for (int i = 0; i < 6; i++) {
                            if (i > 0) oss << ":";
                            oss << std::hex << std::setw(2) << std::setfill('0')
                                << (int)(unsigned char)ifr.ifr_hwaddr.sa_data[i];
                        }
                        mac = oss.str();
                        std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
                    }
                    close(fd);
                }
                break;
            }
        }
        freeifaddrs(ifaddr);
    }
#endif

    return mac;
}

std::string DefaultHardwareProvider::get_cpu_info() const {
    std::string cpu;

#ifdef _WIN32
    // Try wmic
    FILE* fp = _popen("wmic cpu get Name", "r");
    if (fp) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), fp)) {
            std::string line = buffer;
            if (line.find("CPU") == std::string::npos &&
                line.find("Name") == std::string::npos &&
                !line.empty()) {
                // Remove trailing whitespace
                while (!line.empty() && std::isspace(line.back())) line.pop_back();
                if (!line.empty()) {
                    cpu = line;
                    break;
                }
            }
        }
        _pclose(fp);
    }

    // Fallback to environment variable
    if (cpu.empty()) {
        const char* env = std::getenv("PROCESSOR_IDENTIFIER");
        if (env) {
            cpu = env;
        }
    }

#elif defined(__APPLE__)
    char buffer[256];
    size_t size = sizeof(buffer);
    if (sysctlbyname("machdep.cpu.brand_string", buffer, &size, nullptr, 0) == 0) {
        cpu = buffer;
    }

#else  // Linux
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), fp)) {
            std::string line = buffer;
            if (line.compare(0, 10, "model name") == 0) {
                size_t colon = line.find(':');
                if (colon != std::string::npos) {
                    cpu = line.substr(colon + 1);
                    // Trim whitespace
                    while (!cpu.empty() && std::isspace(cpu.back())) cpu.pop_back();
                    while (!cpu.empty() && std::isspace(cpu.front())) cpu.erase(cpu.begin());
                    break;
                }
            }
        }
        fclose(fp);
    }
#endif

    return cpu;
}

std::string DefaultHardwareProvider::get_memory_info() const {
    std::string memory;

#ifdef _WIN32
    MEMORYSTATUSEX memex;
    memex.dwLength = sizeof(memex);
    if (GlobalMemoryStatusEx(&memex)) {
        uint64_t bytes = memex.ullTotalPhys;
        std::ostringstream oss;
        if (bytes >= 1024ULL * 1024 * 1024) {
            oss << (bytes / (1024ULL * 1024 * 1024)) << "GB";
        } else if (bytes >= 1024ULL * 1024) {
            oss << (bytes / (1024ULL * 1024)) << "MB";
        } else {
            oss << (bytes / 1024) << "KB";
        }
        memory = oss.str();
    }

#elif defined(__APPLE__)
    uint64_t bytes;
    size_t size = sizeof(bytes);
    if (sysctlbyname("hw.memsize", &bytes, &size, nullptr, 0) == 0) {
        std::ostringstream oss;
        if (bytes >= 1024ULL * 1024 * 1024) {
            oss << (bytes / (1024ULL * 1024 * 1024)) << "GB";
        } else if (bytes >= 1024ULL * 1024) {
            oss << (bytes / (1024ULL * 1024)) << "MB";
        } else {
            oss << (bytes / 1024) << "KB";
        }
        memory = oss.str();
    }

#else  // Linux
    FILE* fp = fopen("/proc/meminfo", "r");
    if (fp) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), fp)) {
            std::string line = buffer;
            if (line.compare(0, 8, "MemTotal") == 0) {
                // Parse: MemTotal:       16384000 kB
                size_t colon = line.find(':');
                if (colon != std::string::npos) {
                    std::string value_str = line.substr(colon + 1);
                    // Remove non-digit characters
                    std::string digits;
                    for (char c : value_str) {
                        if (std::isdigit(c)) digits += c;
                    }
                    if (!digits.empty()) {
                        uint64_t kb = std::stoull(digits);
                        uint64_t bytes = kb * 1024;
                        std::ostringstream oss;
                        if (bytes >= 1024ULL * 1024 * 1024) {
                            oss << (bytes / (1024ULL * 1024 * 1024)) << "GB";
                        } else if (bytes >= 1024ULL * 1024) {
                            oss << (bytes / (1024ULL * 1024)) << "MB";
                        } else {
                            oss << (bytes / 1024) << "KB";
                        }
                        memory = oss.str();
                    }
                }
                break;
            }
        }
        fclose(fp);
    }
#endif

    return memory;
}

} // namespace license_manager

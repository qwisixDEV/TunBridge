#include "tunbridge/download.hpp"

#include "tunbridge/core.hpp"

#include <curl/curl.h>
#include <zlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tb {
namespace {

bool fail(std::string* err, std::string text) {
    if (err) *err = std::move(text);
    return false;
}

constexpr const char* kApiLatest =
    "https://api.github.com/repos/xjasonlyu/tun2socks/releases/latest";
constexpr const char* kApiPinned =
    "https://api.github.com/repos/xjasonlyu/tun2socks/releases/tags/v2.7.0";
constexpr const char* kReleasePrefix =
    "https://github.com/xjasonlyu/tun2socks/releases/download/";
constexpr std::size_t kMaxJson = 4u << 20;
constexpr std::size_t kMaxZip = 256u << 20;
constexpr std::size_t kMaxBinary = 128u << 20;

bool write_all(int fd, const void* data, std::size_t len) {
    const char* p = static_cast<const char*>(data);
    std::size_t offset = 0;
    while (offset < len) {
        const ssize_t n = ::write(fd, p + offset, len - offset);
        if (n > 0) { offset += static_cast<std::size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool make_dirs(const std::string& path) {
    if (path.empty()) return false;
    std::string current;
    std::size_t i = 0;
    if (path.front() == '/') { current = "/"; i = 1; }
    while (i <= path.size()) {
        const std::size_t next = path.find('/', i);
        const std::string part = path.substr(i, next == std::string::npos ? std::string::npos : next - i);
        if (!part.empty()) {
            if (!current.empty() && current.back() != '/') current.push_back('/');
            current += part;
            if (::mkdir(current.c_str(), 0755) != 0 && errno != EEXIST) return false;
            struct stat st{};
            if (::stat(current.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return false;
        }
        if (next == std::string::npos) break;
        i = next + 1;
    }
    return true;
}

struct TempFile {
    std::string path;
    ~TempFile() {
        if (!path.empty()) (void)::unlink(path.c_str());
    }
};

bool create_temp(const std::string& directory, const char* pattern, TempFile* out, int* fdOut) {
    const std::string tmpl = directory + "/" + pattern;
    std::vector<char> name(tmpl.begin(), tmpl.end());
    name.push_back('\0');
    const int fd = ::mkstemp(name.data());
    if (fd < 0) return false;
    out->path = name.data();
    *fdOut = fd;
    return true;
}

std::size_t string_write(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    const std::size_t n = size * nmemb;
    auto* target = static_cast<std::string*>(userdata);
    if (target->size() + n > kMaxJson) return 0;
    target->append(ptr, n);
    return n;
}

struct FileSink {
    int fd{-1};
    std::size_t written{0};
};

std::size_t file_write(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    const std::size_t n = size * nmemb;
    auto* sink = static_cast<FileSink*>(userdata);
    if (!write_all(sink->fd, ptr, n)) return 0;
    sink->written += n;
    return n;
}

bool http_get(const std::string& url,
              std::size_t (*callback)(char*, std::size_t, std::size_t, void*),
              void* sink, std::string* err) {
    static std::once_flag initFlag;
    std::call_once(initFlag, [] { (void)curl_global_init(CURL_GLOBAL_DEFAULT); });

    CURL* handle = curl_easy_init();
    if (handle == nullptr) {
        if (err) *err = "Не удалось инициализировать libcurl";
        return false;
    }
    curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(handle, CURLOPT_USERAGENT, "TunBridge");
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 180L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, callback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, sink);

    const CURLcode code = curl_easy_perform(handle);
    long http = 0;
    (void)curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http);
    curl_easy_cleanup(handle);

    if (code != CURLE_OK) {
        if (err) {
            *err = std::string("Ошибка загрузки: ") + curl_easy_strerror(code);
            if (http != 0) *err += " (HTTP " + std::to_string(http) + ")";
        }
        return false;
    }
    if (http < 200 || http >= 300) {
        if (err) *err = "Неожиданный HTTP-код: " + std::to_string(http);
        return false;
    }
    return true;
}

bool http_get_string(const std::string& url, std::string* out, std::string* err) {
    out->clear();
    return http_get(url, &string_write, out, err);
}

bool http_get_file(const std::string& url, int fd, std::string* err) {
    FileSink sink;
    sink.fd = fd;
    if (!http_get(url, &file_write, &sink, err)) return false;
    if (sink.written == 0) {
        if (err) *err = "Загружен пустой файл";
        return false;
    }
    return true;
}

std::string json_unescape(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (std::size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] != '\\') { out.push_back(raw[i]); continue; }
        if (++i >= raw.size()) break;
        switch (raw[i]) {
            case '"':  out.push_back('"');  break;
            case '\\': out.push_back('\\'); break;
            case '/':  out.push_back('/');  break;
            case 'n':  out.push_back('\n'); break;
            case 'r':  out.push_back('\r'); break;
            case 't':  out.push_back('\t'); break;
            case 'b':  out.push_back('\b'); break;
            case 'f':  out.push_back('\f'); break;
            case 'u': {
                if (i + 4 >= raw.size()) break;
                unsigned code = 0;
                bool ok = true;
                for (int k = 1; k <= 4; ++k) {
                    const char c = raw[i + k];
                    code <<= 4;
                    if (c >= '0' && c <= '9') code |= static_cast<unsigned>(c - '0');
                    else if (c >= 'a' && c <= 'f') code |= static_cast<unsigned>(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') code |= static_cast<unsigned>(c - 'A' + 10);
                    else { ok = false; break; }
                }
                i += 4;
                if (!ok) break;
                if (code < 0x80) {
                    out.push_back(static_cast<char>(code));
                } else if (code < 0x800) {
                    out.push_back(static_cast<char>(0xC0 | (code >> 6)));
                    out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                } else {
                    out.push_back(static_cast<char>(0xE0 | (code >> 12)));
                    out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                }
                break;
            }
            default: out.push_back(raw[i]); break;
        }
    }
    return out;
}

bool json_string(std::string_view json, std::string_view key, std::string& out,
                 std::size_t from = 0, std::size_t* valueEnd = nullptr) {
    std::string needle = "\"";
    needle.append(key).push_back('"');
    const std::size_t found = json.find(needle, from);
    if (found == std::string_view::npos) return false;
    std::size_t p = found + needle.size();
    const auto skipSpace = [&] {
        while (p < json.size() && (json[p] == ' ' || json[p] == '\t' ||
                                   json[p] == '\n' || json[p] == '\r')) ++p;
    };
    skipSpace();
    if (p >= json.size() || json[p] != ':') return false;
    ++p;
    skipSpace();
    if (p >= json.size() || json[p] != '"') return false;
    ++p;
    std::string raw;
    while (p < json.size()) {
        const char c = json[p];
        if (c == '"') { ++p; break; }
        if (c == '\\') {
            raw.push_back(c);
            if (p + 1 < json.size()) raw.push_back(json[p + 1]);
            p += 2;
            continue;
        }
        raw.push_back(c);
        ++p;
    }
    out = json_unescape(raw);
    if (valueEnd) *valueEnd = p;
    return true;
}

std::string lower_copy(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char c : text) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

bool valid_digest(std::string_view digest) {
    if (digest.size() != 64) return false;
    for (const char c : digest) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

struct Asset {
    std::string name;
    std::string url;
    std::string digest; // lowercase hex, without "sha256:"
};

bool parse_assets(std::string_view json, std::vector<Asset>& out) {
    const std::size_t assets = json.find("\"assets\"");
    if (assets == std::string_view::npos) return false;
    const std::size_t array = json.find('[', assets);
    if (array == std::string_view::npos) return false;

    std::size_t pos = array;
    while (pos < json.size()) {
        if (json[pos] == ']') break;
        if (json[pos] != '{') { ++pos; continue; }
        const std::size_t begin = pos;
        int depth = 0;
        bool inString = false;
        bool escaped = false;
        while (pos < json.size()) {
            const char c = json[pos];
            if (inString) {
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') inString = false;
                ++pos;
                continue;
            }
            if (c == '"') { inString = true; ++pos; continue; }
            if (c == '{') ++depth;
            if (c == '}') {
                --depth;
                ++pos;
                if (depth == 0) break;
                continue;
            }
            ++pos;
        }
        const std::string_view object = json.substr(begin, pos - begin);
        Asset asset;
        if (json_string(object, "name", asset.name) &&
            json_string(object, "browser_download_url", asset.url)) {
            std::string digest;
            if (json_string(object, "digest", digest) &&
                lower_copy(digest).rfind("sha256:", 0) == 0)
                asset.digest = lower_copy(digest.substr(7));
            out.push_back(std::move(asset));
        }
    }
    return !out.empty();
}

bool find_asset_in(const std::string& apiUrl, const std::string& wanted,
                   Asset* found, std::string* tag, std::string* err) {
    std::string json;
    std::string detail;
    if (!http_get_string(apiUrl, &json, &detail)) {
        if (err) *err = detail;
        return false;
    }
    std::vector<Asset> assets;
    if (!parse_assets(json, assets)) {
        if (err) *err = "Не удалось разобрать список ассетов GitHub API";
        return false;
    }
    std::string releaseTag;
    if (json_string(json, "tag_name", releaseTag) && tag) *tag = releaseTag;
    for (const auto& asset : assets) {
        if (asset.name != wanted || !valid_digest(asset.digest)) continue;
        if (asset.url.rfind(kReleasePrefix, 0) != 0) continue;
        *found = asset;
        return true;
    }
    if (err) *err = "GitHub API не вернул SHA-256 для " + wanted;
    return false;
}

std::string target_asset_name() {
    struct utsname info{};
    if (::uname(&info) != 0) return {};
    const std::string machine = info.machine;
    if (machine == "x86_64" || machine == "amd64") return "tun2socks-linux-amd64.zip";
    if (machine == "aarch64" || machine == "arm64") return "tun2socks-linux-arm64.zip";
    return {};
}

using Bytes = std::vector<unsigned char>;

bool get16(const Bytes& data, std::size_t pos, std::uint16_t* out) {
    if (pos + 2 > data.size()) return false;
    *out = static_cast<std::uint16_t>(data[pos] | (data[pos + 1] << 8));
    return true;
}

bool get32(const Bytes& data, std::size_t pos, std::uint32_t* out) {
    if (pos + 4 > data.size()) return false;
    *out = static_cast<std::uint32_t>(data[pos]) |
           (static_cast<std::uint32_t>(data[pos + 1]) << 8) |
           (static_cast<std::uint32_t>(data[pos + 2]) << 16) |
           (static_cast<std::uint32_t>(data[pos + 3]) << 24);
    return true;
}

struct ZipEntry {
    std::string name;
    std::uint16_t method{0};
    std::uint32_t crc{0};
    std::uint64_t compressed{0};
    std::uint64_t uncompressed{0};
    std::uint64_t localOffset{0};
};

bool find_zip_entry(const Bytes& data, const std::string& binaryName,
                    ZipEntry* found, std::string* err) {
    if (data.size() < 22) return fail(err, "Архив слишком мал");
    const std::size_t lowest = data.size() > 65557 ? data.size() - 65557 : 0;
    std::size_t eocd = std::string::npos;
    for (std::size_t pos = data.size() - 22;; --pos) {
        std::uint32_t signature = 0;
        if (get32(data, pos, &signature) && signature == 0x06054b50) { eocd = pos; break; }
        if (pos == lowest) break;
    }
    if (eocd == std::string::npos) return fail(err, "Не найден каталог ZIP (EOCD)");

    std::uint16_t total = 0;
    std::uint32_t directoryOffset = 0;
    if (!get16(data, eocd + 10, &total) || !get32(data, eocd + 16, &directoryOffset))
        return fail(err, "Повреждён каталог ZIP");

    std::size_t pos = directoryOffset;
    bool exactMatch = false;
    for (std::uint16_t i = 0; i < total; ++i) {
        std::uint32_t signature = 0;
        if (!get32(data, pos, &signature) || signature != 0x02014b50) break;
        ZipEntry entry;
        std::uint16_t nameLen = 0, extraLen = 0, commentLen = 0;
        std::uint32_t compressed32 = 0, uncompressed32 = 0, local32 = 0;
        if (!get16(data, pos + 10, &entry.method) ||
            !get32(data, pos + 16, &entry.crc) ||
            !get32(data, pos + 20, &compressed32) ||
            !get32(data, pos + 24, &uncompressed32) ||
            !get16(data, pos + 28, &nameLen) ||
            !get16(data, pos + 30, &extraLen) ||
            !get16(data, pos + 32, &commentLen) ||
            !get32(data, pos + 42, &local32) ||
            pos + 46 + nameLen > data.size())
            return fail(err, "Повреждённая запись ZIP");
        entry.name.assign(reinterpret_cast<const char*>(data.data() + pos + 46), nameLen);
        entry.compressed = compressed32;
        entry.uncompressed = uncompressed32;
        entry.localOffset = local32;
        const std::size_t slash = entry.name.find_last_of("/\\");
        const std::string base = slash == std::string::npos
                                     ? entry.name
                                     : entry.name.substr(slash + 1);
        if (base == binaryName) {
            if (entry.name == binaryName || exactMatch == false) {
                *found = entry;
                exactMatch = entry.name == binaryName;
                if (exactMatch) break;
            }
        }
        pos += 46 + nameLen + extraLen + commentLen;
    }
    if (found->name.empty()) return fail(err, "В архиве нет файла " + binaryName);
    return true;
}

bool extract_zip_entry(const Bytes& zip, const ZipEntry& entry, Bytes* out, std::string* err) {
    if (entry.uncompressed > kMaxBinary || entry.compressed > kMaxZip)
        return fail(err, "Слишком большой файл в архиве ZIP");
    std::size_t pos = static_cast<std::size_t>(entry.localOffset);
    std::uint32_t signature = 0;
    if (!get32(zip, pos, &signature) || signature != 0x04034b50)
        return fail(err, "Повреждён локальный заголовок ZIP");
    std::uint16_t nameLen = 0, extraLen = 0;
    if (!get16(zip, pos + 26, &nameLen) || !get16(zip, pos + 28, &extraLen))
        return fail(err, "Повреждён локальный заголовок ZIP");
    const std::size_t dataOffset = pos + 30 + nameLen + extraLen;
    const std::size_t compressed = static_cast<std::size_t>(entry.compressed);
    if (dataOffset > zip.size() || compressed > zip.size() - dataOffset)
        return fail(err, "Усечённые данные ZIP");

    out->clear();
    if (entry.uncompressed > 0) out->reserve(static_cast<std::size_t>(entry.uncompressed));
    const unsigned char* begin = zip.data() + dataOffset;

    if (entry.method == 0) { // stored
        out->assign(begin, begin + compressed);
    } else if (entry.method == 8) { // deflate
        z_stream stream{};
        if (::inflateInit2(&stream, -MAX_WBITS) != Z_OK)
            return fail(err, "Не удалось инициализировать zlib");
        stream.next_in = reinterpret_cast<Bytef*>(const_cast<unsigned char*>(begin));
        stream.avail_in = static_cast<uInt>(compressed);
        std::array<unsigned char, 65536> buffer{};
        int rc = Z_OK;
        while (rc == Z_OK || rc == Z_BUF_ERROR) {
            stream.next_out = buffer.data();
            stream.avail_out = static_cast<uInt>(buffer.size());
            rc = ::inflate(&stream, Z_NO_FLUSH);
            const std::size_t produced = buffer.size() - stream.avail_out;
            if (out->size() + produced > kMaxBinary) { rc = Z_DATA_ERROR; break; }
            out->insert(out->end(), buffer.begin(), buffer.begin() + produced);
            if (rc == Z_STREAM_END) break;
            if (rc != Z_OK && rc != Z_BUF_ERROR) break;
            if (produced == 0 && stream.avail_in == 0) break;
        }
        ::inflateEnd(&stream);
        if (rc != Z_STREAM_END) return fail(err, "Ошибка распаковки deflate");
    } else {
        return fail(err, "Неподдерживаемый метод сжатия ZIP");
    }

    if (out->size() != entry.uncompressed)
        return fail(err, "Неверный размер распакованного файла");
    if (::crc32(0, out->data(), static_cast<uInt>(out->size())) != entry.crc)
        return fail(err, "Контрольная сумма CRC32 файла не совпала");
    return true;
}

bool read_whole_file(const std::string& path, Bytes* out, std::string* err) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fail(err, std::string("open: ") + std::strerror(errno));
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || static_cast<std::uint64_t>(st.st_size) > kMaxZip) {
        ::close(fd);
        return fail(err, "Некорректный размер архива ZIP");
    }
    out->resize(static_cast<std::size_t>(st.st_size));
    std::size_t offset = 0;
    while (offset < out->size()) {
        const ssize_t n = ::read(fd, out->data() + offset, out->size() - offset);
        if (n > 0) { offset += static_cast<std::size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        ::close(fd);
        return fail(err, std::string("read: ") + std::strerror(errno));
    }
    ::close(fd);
    return true;
}

bool install_binary(const Bytes& bytes, const std::string& destination, std::string* err) {
    const std::size_t slash = destination.find_last_of('/');
    const std::string directory = slash == std::string::npos ? std::string(".") : destination.substr(0, slash);
    if (!make_dirs(directory)) return fail(err, std::string("mkdir: ") + std::strerror(errno));

    const std::string tmpl = directory + "/.tun2socks-XXXXXX";
    std::vector<char> name(tmpl.begin(), tmpl.end());
    name.push_back('\0');
    const int fd = ::mkstemp(name.data());
    if (fd < 0) return fail(err, std::string("mkstemp: ") + std::strerror(errno));
    bool ok = write_all(fd, bytes.data(), bytes.size());
    if (ok && ::fchmod(fd, 0755) != 0) ok = false;
    if (ok && ::fsync(fd) != 0) ok = false;
    ::close(fd);
    if (!ok) {
        (void)::unlink(name.data());
        return fail(err, "Не удалось записать tun2socks");
    }
    if (::rename(name.data(), destination.c_str()) != 0) {
        (void)::unlink(name.data());
        return fail(err, std::string("rename: ") + std::strerror(errno));
    }
    const int dirFd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirFd >= 0) {
        (void)::fsync(dirFd);
        ::close(dirFd);
    }
    return true;
}

} // namespace

std::string tun2socks_path() {
    std::string base;
    const char* data = std::getenv("XDG_DATA_HOME");
    if (data && *data) {
        base = data;
    } else {
        const char* home = std::getenv("HOME");
        base = (home && *home) ? std::string(home) + "/.local/share" : "/root/.local/share";
    }
    return base + "/tunbridge/bin/tun2socks";
}

bool download_tun2socks(std::string* status, std::string* error) {
    const auto say = [&](std::string message) {
        if (status) *status = std::move(message);
    };
    const auto failWith = [&](std::string message) {
        if (error) *error = message;
        say(std::move(message));
        return false;
    };

    const std::string wanted = target_asset_name();
    if (wanted.empty())
        return failWith("Неподдерживаемая архитектура процессора для tun2socks");

    say("Запрос информации о последнем релизе tun2socks...");
    Asset asset;
    std::string tag;
    std::string detail;
    bool found = find_asset_in(kApiLatest, wanted, &asset, &tag, &detail);
    if (!found) {
        say("Актуальный релиз без SHA-256 — запрос закреплённой версии v2.7.0...");
        detail.clear();
        found = find_asset_in(kApiPinned, wanted, &asset, &tag, &detail);
    }
    // No hardcoded digest: without the published SHA-256 the download is
    // rejected instead of installing unverified code.
    if (!found)
        return failWith(detail.empty()
                            ? "GitHub API не вернул SHA-256 для " + wanted + ". Загрузка отклонена"
                            : "Не удалось получить SHA-256 для " + wanted + ": " + detail);

    say("Загрузка архива " + asset.name + (tag.empty() ? std::string() : " (" + tag + ")") + "...");
    const std::string tempDir = [] {
        const char* runtime = std::getenv("XDG_RUNTIME_DIR");
        if (runtime && *runtime) return std::string(runtime);
        const char* tmp = std::getenv("TMPDIR");
        return std::string(tmp && *tmp ? tmp : "/tmp");
    }();
    TempFile zipFile;
    int zipFd = -1;
    if (!create_temp(tempDir, "tunbridge-XXXXXX.zip", &zipFile, &zipFd))
        return failWith(std::string("Не удалось создать временный файл: ") + std::strerror(errno));
    if (!http_get_file(asset.url, zipFd, &detail)) {
        ::close(zipFd);
        return failWith(detail);
    }
    if (::fsync(zipFd) != 0) {
        ::close(zipFd);
        return failWith("Не удалось записать временный архив на диск");
    }
    ::close(zipFd);

    say("Проверка SHA-256 загруженного архива...");
    char actual[65]{};
    if (!sha256_file_hex(zipFile.path, actual))
        return failWith("Не удалось вычислить SHA-256 архива");
    if (lower_copy(actual) != asset.digest)
        return failWith("SHA-256 не совпал: получен " + std::string(actual) +
                        ", ожидался " + asset.digest);

    say("Распаковка tun2socks из архива...");
    Bytes zip;
    if (!read_whole_file(zipFile.path, &zip, &detail)) return failWith(detail);
    ZipEntry entry;
    if (!find_zip_entry(zip, "tun2socks", &entry, &detail)) return failWith(detail);
    Bytes binary;
    if (!extract_zip_entry(zip, entry, &binary, &detail)) return failWith(detail);
    if (binary.empty()) return failWith("Пустой исполняемый файл tun2socks в архиве");

    say("Установка tun2socks...");
    const std::string destination = tun2socks_path();
    if (!install_binary(binary, destination, &detail)) return failWith(detail);

    say("Готово: tun2socks установлен в " + destination);
    return true;
}

} // namespace tb

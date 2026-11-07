#include "PatternLoader.h"
#include "OSTPlatform/include/Memory.h"
#include "OSTPlatform/include/Numbers.h"
#include "Utils/Logging/Log.h"
#include "Utils/SteamMetadata/RemoteToml.h"
#include "Utils/SteamMetadata/SteamDiagnostics.h"
#include "Utils/Support/FnvHash.h"

#include <cstring>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <toml++/toml.hpp>

// ---- compile-time sanity checks for FNV-1a table keys ----
// If the steam-monitor bot uses the same algorithm these must hold.
static_assert(Fnv1aHash("BBuildAndAsyncSendFrame") == 0x82428E37u,
              "FNV-1a mismatch for BBuildAndAsyncSendFrame");
static_assert(Fnv1aHash("BuildDepotDependency") == 0xC37F2D8Eu,
              "FNV-1a mismatch for BuildDepotDependency");

namespace {

// ---- per-function pattern record ----
struct PatternEntry {
    std::string name;
    uintptr_t   rva = 0;   // 0 = not present in file
    std::string sig;        // empty = not present in file
};

// key = Fnv1aHash(funcName)
using PatternMap = std::unordered_map<uint32_t, PatternEntry>;

// module → its pattern map
static std::unordered_map<OSTPlatform::DynamicLibrary::ModuleHandle, PatternMap> g_moduleMaps;

// Modules whose Load() call failed (popup already shown). FindPattern
// silently returns nullptr for these — without re-logging or adding the
// function to g_missingFunctions — so we don't follow one "TOML missing"
// popup with a second popup listing every dependent hook.
static std::unordered_set<OSTPlatform::DynamicLibrary::ModuleHandle> g_failedModules;

// functions whose names were not found during FindPattern
static std::vector<std::string> g_missingFunctions;

// ---- byte-pattern scanner ----

static bool ParseSig(const std::string& str,
                     std::vector<uint8_t>& bytes,
                     std::vector<uint8_t>& mask)
{
    bytes.clear();
    mask.clear();
    for (const char* p = str.c_str(); *p; ) {
        if (*p == ' ' || *p == '\t' || *p == ',') { ++p; continue; }
        if (p[0] == '?' && p[1] == '?') {
            bytes.push_back(0); mask.push_back(0); p += 2; continue;
        }
        char hi = p[0], lo = p[1];
        if (!hi || !lo) return false;
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = nib(hi), l = nib(lo);
        if (h < 0 || l < 0) return false;
        bytes.push_back(static_cast<uint8_t>((h << 4) | l));
        mask.push_back(1);
        p += 2;
    }
    return !bytes.empty();
}

static void* ScanModule(OSTPlatform::DynamicLibrary::ModuleHandle module,
                        const std::vector<uint8_t>& bytes,
                        const std::vector<uint8_t>& mask)
{
    const auto image = OSTPlatform::Memory::GetModuleImage(module);
    if (!image) return nullptr;

    auto* base = image->base;
    size_t size = image->size;
    size_t patLen = bytes.size();
    if (size < patLen) return nullptr;

    for (size_t i = 0; i <= size - patLen; ++i) {
        bool found = true;
        for (size_t j = 0; j < patLen; ++j) {
            if (mask[j] && base[i + j] != bytes[j]) { found = false; break; }
        }
        if (found) return base + i;
    }
    return nullptr;
}

// ---- TOML pattern parser ----

// Section keys are hex literals like "0x82428E37"; each section is a table
// with optional `name`, `rva` (hex string), and `sig` (IDA-style bytes).
static PatternMap TableToPatternMap(const toml::table& tbl)
{
    PatternMap map;
    map.reserve(tbl.size());
    for (auto& [rawKey, val] : tbl) {
        if (!val.is_table()) continue;
        auto& sub = *val.as_table();

        const auto parsedKey = OSTPlatform::Numbers::ParseHexUInt32(std::string(rawKey));
        if (!parsedKey) continue;
        const uint32_t hashKey = *parsedKey;

        PatternEntry entry;
        if (auto v = sub["name"].value<std::string>()) entry.name = *v;
        if (auto v = sub["rva"].value<std::string>()) {
            if (const auto rva = OSTPlatform::Numbers::ParseHexUInt64(*v)) {
                entry.rva = static_cast<uintptr_t>(*rva);
            }
        }
        if (auto v = sub["sig"].value<std::string>()) entry.sig = *v;

        map[hashKey] = std::move(entry);
    }
    return map;
}

static PatternMap ParsePatternString(std::string_view body,
                                     std::string* outError = nullptr)
{
    try {
        return TableToPatternMap(toml::parse(body));
    } catch (const toml::parse_error& e) {
        if (outError) *outError = e.description();
        return {};
    }
}

// ---- popup helpers (detached threads so we never block Steam) ----

// Surface a missing pattern file to the user, with enough detail to either
// (a) drop a file in manually, (b) check the upstream repo, or (c) file
// an actionable bug report.  We deliberately only disable hooks for the
// failing module — the rest of OpenSteamTool keeps working.
static void ShowDownloadFailedPopup(const std::string& dllName,
                                    const std::string& sha256,
                                    const std::string& component)
{
    SteamDiagnostics::ShowWarning(
        "OpenSteamTool - Unsupported Steam Version",
        "OpenSteamTool: signature file not found for " + dllName + ".\n\n"
        "Hooks that depend on " + dllName + " are disabled for this session; "
        "other modules are unaffected.\n\n"
        "You can:\n"
        "  1. Wait for the next signature update, then restart Steam.\n"
        "  2. Drop a matching TOML at:\n"
        "       <Steam>\\opensteamtool\\pattern\\" + component + "\\" + sha256 + ".toml\n"
        "  3. Check upstream:\n"
        "       https://github.com/madoiscool/steam-monitor/tree/pattern/" + component + "\n"
        "  4. Report the diagnostics below:\n"
        "       https://github.com/madoiscool/BetterSteamTools/issues");
}

} // namespace

// ---- public API ----

namespace PatternLoader {

    constexpr const char* kPatternChannel = "pattern";

bool Load(OSTPlatform::DynamicLibrary::ModuleHandle module, const std::string& dllPath, const std::string& component)
{
    namespace fs = std::filesystem;

    // Delegate fetch + cache + mirror fallback to RemoteToml.
    RemoteToml::Result r = RemoteToml::Fetch({
        kPatternChannel,
        component,
        dllPath,
    });

    if (r.ok) {
        std::string parseErr;
        PatternMap map = ParsePatternString(r.body, &parseErr);
        if (!map.empty()) {
            LOG_INFO("PatternLoader: loaded {} patterns for {} ({})",
                     map.size(), component, r.fromCache ? "cache fallback" : "remote");
            g_moduleMaps[module] = std::move(map);
            return true;
        }
        LOG_WARN("PatternLoader: TOML for {} parsed empty ({})",
                 component, parseErr.empty() ? "no entries" : parseErr);
    }

    // Total failure — popup + disable module's hooks.
    std::string dllName = fs::path(dllPath).filename().string();
    std::string sha     = r.sha256.empty() ? "(hash failed)" : r.sha256;
    ShowDownloadFailedPopup(dllName, sha, component);
    g_failedModules.insert(module);
    return false;
}

void* FindPattern(OSTPlatform::DynamicLibrary::ModuleHandle module, const char* funcName)
{
    // If the whole module's pattern file failed to load, stay quiet — the
    // user already saw one popup and the main.log already has the warning.
    // No point amplifying that into one log line per hook plus a second
    // "missing functions" popup later.
    if (g_failedModules.count(module)) {
        return nullptr;
    }

    uint32_t key = Fnv1aHash(funcName);

    auto mapIt = g_moduleMaps.find(module);
    if (mapIt == g_moduleMaps.end()) {
        // Load() was never called for this module.
        LOG_WARN("PatternLoader: FindPattern called for module that was never loaded "
                 "('{}')", funcName);
        g_missingFunctions.emplace_back(funcName);
        return nullptr;
    }

    auto& map = mapIt->second;
    auto entryIt = map.find(key);
    if (entryIt == map.end()) {
        LOG_WARN("PatternLoader: no entry for '{}' (key=0x{:08X})", funcName, key);
        g_missingFunctions.emplace_back(funcName);
        return nullptr;
    }

    const PatternEntry& entry = entryIt->second;

    // Priority 1: RVA direct offset
    if (entry.rva != 0) {
        void* addr = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(module) + entry.rva);
        LOG_DEBUG("PatternLoader: {} resolved via RVA 0x{:X}", funcName, entry.rva);
        return addr;
    }

    // Priority 2: byte-signature scan
    if (!entry.sig.empty()) {
        std::vector<uint8_t> bytes, mask;
        if (ParseSig(entry.sig, bytes, mask)) {
            void* addr = ScanModule(module, bytes, mask);
            if (addr) {
                uintptr_t rva = reinterpret_cast<uintptr_t>(addr) -
                                reinterpret_cast<uintptr_t>(module);
                LOG_DEBUG("PatternLoader: {} resolved via sig @ RVA 0x{:X}",
                          funcName, rva);
                return addr;
            }
            LOG_WARN("PatternLoader: sig scan miss for '{}' (pattern parsed OK, "
                     "no match in module image)", funcName);
        } else {
            LOG_WARN("PatternLoader: malformed sig for '{}': '{}'",
                     funcName, entry.sig);
        }
    } else {
        LOG_WARN("PatternLoader: entry for '{}' has neither rva nor sig", funcName);
    }

    g_missingFunctions.emplace_back(funcName);
    return nullptr;
}

void** FindVTable(OSTPlatform::DynamicLibrary::ModuleHandle module, const char* className)
{
    const auto image = OSTPlatform::Memory::GetModuleImage(module);
    if (!image) return nullptr;
    const uint8_t* base = image->base;
    const size_t size = image->size;
    const std::string name = std::string(".?AV") + className + "@@";

    // TypeDescriptor { vftable*, spare*, char name[] }
    for (size_t n = 16; n + name.size() < size; n += 8) {
        if (std::memcmp(base + n, name.c_str(), name.size() + 1) != 0) continue;
        const uint32_t tdRva = static_cast<uint32_t>(n - 16);

        // CompleteObjectLocator { signature 1, offset 0 (primary), cdOffset, pTypeDescriptor, pClassDescriptor, pSelf }, then the vtable.
        for (size_t c = 0; c + 24 <= size; c += 4) {
            uint32_t col[6];
            std::memcpy(col, base + c, sizeof(col));
            if (col[0] != 1 || col[1] != 0 || col[3] != tdRva || col[5] != c) continue;
            const uint64_t colVa = reinterpret_cast<uintptr_t>(base) + c;
            for (size_t v = 0; v + 16 <= size; v += 8)
                if (std::memcmp(base + v, &colVa, sizeof(colVa)) == 0)
                    return reinterpret_cast<void**>(const_cast<uint8_t*>(base + v + 8));
        }
    }
    LOG_WARN("PatternLoader: no vtable for class '{}'", className);
    return nullptr;
}

void** FindVirtualReferencing(OSTPlatform::DynamicLibrary::ModuleHandle module, void** vtable, const void* target)
{
    const auto image = OSTPlatform::Memory::GetModuleImage(module);
    if (!image || !vtable || !target) return nullptr;
    for (void** slot = vtable; *slot >= image->base && *slot < image->base + image->size; ++slot) {
        const auto body = OSTPlatform::Memory::FunctionBody(*slot);
        for (size_t i = 0; i + 7 <= body.size(); ++i) {
            if ((body[i] & 0xFB) != 0x48 || body[i + 1] != 0x8D || (body[i + 2] & 0xC7) != 0x05) continue;   // lea r64, [rip+disp32]
            int32_t disp;
            std::memcpy(&disp, body.data() + i + 3, sizeof(disp));
            if (body.data() + i + 7 + disp == target) return slot;
        }
    }
    return nullptr;
}

void** FindVirtualNamed(OSTPlatform::DynamicLibrary::ModuleHandle module, void** vtable, const char* name)
{
    const auto image = OSTPlatform::Memory::GetModuleImage(module);
    if (!image || !vtable || !name) return nullptr;
    // Whole strings only; the binary may hold several copies.
    const std::string_view text(reinterpret_cast<const char*>(image->base), image->size);
    const std::string_view needle(name, std::strlen(name) + 1);
    for (size_t at = text.find(needle); at != std::string_view::npos; at = text.find(needle, at + 1))
        if (at > 0 && text[at - 1] == 0)
            if (void** slot = FindVirtualReferencing(module, vtable, text.data() + at)) return slot;
    return nullptr;
}

void ReportMissingFunctions()
{
    if (g_missingFunctions.empty()) return;

    // Build the list
    std::string list;
    for (const auto& name : g_missingFunctions)
        list += "  - " + name + "\n";
    g_missingFunctions.clear();

    SteamDiagnostics::ShowWarning(
        "OpenSteamTool - Missing Signatures",
        "OpenSteamTool: some functions could not be located.\n\n"
        "The following functions were not found in the signature file:\n" +
        list +
        "\nHooks for these functions are disabled for this session.\n\n"
        "Please report this at:\n"
        "https://github.com/madoiscool/BetterSteamTools/issues");
}

} // namespace PatternLoader

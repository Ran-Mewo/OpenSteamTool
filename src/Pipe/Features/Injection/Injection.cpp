#include "Pipe/Features/Injection/Injection.h"

#include "Hook/Hooks_Misc.h"
#include "OSTPlatform/include/Process.h"
#include "OSTPlatform/include/RemoteProcess.h"
#include "Utils/Config/Config.h"
#include "Utils/Config/LuaConfig.h"
#include "Utils/Logging/Log.h"
#include "Utils/RemoteInject.h"

#include <algorithm>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace PipeManager::Injection {
namespace {

    // Keyed on (process, path) so each DLL injects at most once per process
    // while several [[inject]] entries can still target the same game.
    struct InjectedKey {
        ProcessKey  process;
        std::string path;
        bool operator==(const InjectedKey&) const = default;
    };
    struct InjectedKeyHash {
        std::size_t operator()(const InjectedKey& key) const noexcept {
            return ProcessKeyHash{}(key.process) ^ std::hash<std::string>{}(key.path);
        }
    };

    std::mutex g_mutex;
    std::unordered_set<InjectedKey, InjectedKeyHash> g_injected;
    AppId_t                  g_launchAppId = 0;   // the game Steam last launched
    std::vector<std::string> g_launchPaths;       // and the DLLs that matched it

    bool ClaimInjection(const InjectedKey& key) {
        std::scoped_lock lock(g_mutex);
        return g_injected.insert(key).second;
    }

    bool Matches(const Config::InjectDll& dll, AppId_t appId, const std::optional<std::string>& cmdLine) {
        if (!dll.allGames && !LuaConfig::HasDepot(appId, false)) return false;
        if (!dll.whenAppids.empty() && !dll.whenAppids.count(appId)) return false;
        if (!dll.whenCmdline.empty() && (!cmdLine || cmdLine->find(dll.whenCmdline) == std::string::npos)) return false;
        return true;
    }

    // The game's env says 480 under -onlinefix, so publish its real appid for whichever DLL landed.
    void Injected(uint32_t pid, AppId_t appId, const std::string& path, const char* when) {
        LOG_INJECT_INFO("injected pid={} appid={} dll=\"{}\" ({})", pid, appId, std::filesystem::path(path).filename().string(), when);
        if (Hooks_Misc::IsOnlineFixActive()) Hooks_Misc::OnGameInjected(pid, appId);
    }

} // namespace

void OnLaunch(HANDLE process, uint32_t pid, AppId_t appId, const std::string& cmdLine) {
    std::vector<std::string> paths;
    for (const auto& dll : Config::injectDlls)
        if (Matches(dll, appId, cmdLine)) paths.push_back(dll.path);
    {
        std::scoped_lock lock(g_mutex);
        g_launchAppId = appId;
        g_launchPaths = paths;
    }
    // A 32-bit game can't load through our 64-bit LoadLibraryW; its handshake injects it instead.
    BOOL wow64 = FALSE;
    if (IsWow64Process(process, &wow64) && wow64) return;

    const ProcessKey key{ pid, OSTPlatform::Process::GetCreationTime(pid).value_or(0) };
    for (const std::string& path : paths) {
        if (!ClaimInjection({ key, path })) continue;
        if (RemoteInject::LoadDll(process, std::filesystem::path(path).c_str())) Injected(pid, appId, path, "launch");
        else LOG_INJECT_WARN("inject failed pid={} appid={} dll=\"{}\" (launch)", pid, appId, std::filesystem::path(path).filename().string());
    }
}

void Apply(const PipeContext& ctx) {
    if (Config::injectDlls.empty() || !ctx.gameProcess) return;

    // The -onlinefix game runs as 480; match it as its real appid.
    const AppId_t appId = ctx.appId == kOnlineFixAppId && Hooks_Misc::IsOnlineFixActive() ? Hooks_Misc::ResolveAppId() : ctx.appId;
    std::vector<std::string> launched;
    {
        std::scoped_lock lock(g_mutex);
        if (appId == g_launchAppId) launched = g_launchPaths;
    }
    std::optional<std::string> cmdLine;
    for (const auto& dll : Config::injectDlls) {
        // The launched game's processes get its DLLs even where their own command line differs, as when a launcher stub started them.
        if (!std::ranges::count(launched, dll.path)) {
            if (!dll.whenCmdline.empty() && !cmdLine) cmdLine = OSTPlatform::Process::GetProcessCommandLine(ctx.process.pid);
            if (!Matches(dll, appId, cmdLine)) continue;
        }
        if (!ClaimInjection({ ctx.process, dll.path })) continue;

        const auto status = OSTPlatform::RemoteProcess::InjectLibrary(ctx.process.pid, dll.path);
        if (status == OSTPlatform::RemoteProcess::InjectStatus::Ok) Injected(ctx.process.pid, appId, dll.path, "handshake");
        else LOG_INJECT_WARN("inject failed pid={} appid={} status={} dll=\"{}\" (handshake)", ctx.process.pid, appId,
                             OSTPlatform::RemoteProcess::ToString(status), std::filesystem::path(dll.path).filename().string());
    }
}

} // namespace PipeManager::Injection

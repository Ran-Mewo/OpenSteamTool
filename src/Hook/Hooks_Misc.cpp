#include "Hooks_Misc.h"
#include "Hooks_Inject.h"
#include "HookMacros.h"
#include "Utils/HookSupport/VehCommon.h"
#include "dllmain.h"

#include <atomic>
#include <mutex>
#include <windows.h>

namespace {
    // ── Resolve-only functions ─────────────────────────────────────
    RESOLVE_FUNC(CUtlBufferEnsureCapacity, void*, CUtlBuffer* pCUtlBuffer, uint32 newCapacity);

    // ── VEH-captured functions (one-shot int3) ───────────────────────────────
    // On int3 hit, ctx->Rcx is stored to the named output variable.
    CAPTURE_THIS_FUNC(GetAppDataFromAppInfo,  int64,        g_pCAppInfoCache, void*, AppId_t, const char*, uint8*, int32);

    // Assumes one game at a time.  Set by SpawnProcess VEH when -onlinefix
    // is detected; cleared when a non-onlinefix game launches.
    AppId_t   g_OnlineFixRealAppId;
    // True once the game starts SteamNetworkingSockets P2P (see GetAppID handler).
    bool      g_NetworkingSocketsActive;
    // The active game's published strategy, cached so the hot GetAppIDForCurrentPipe hook needs no shared-memory read.
    std::atomic<uint32_t> g_cachedStrategy{0};
    // The injected game's PID, to read its strategy before the cache has it.
    std::atomic<uint32_t> g_onlineFixPid{0};
    std::unordered_map<AppId_t, std::string> g_GameNameCache;

    // ── GetAppIDForCurrentPipe (hooked) ──────────────────────────────────────
    // The session appid that CreateLobby and RequestLobbyList use. The first call also captures g_steamEngine for GetAppIDForCurrentPipeWrap.
    void* g_steamEngine = nullptr;
    HOOK_FUNC(GetAppIDForCurrentPipe, AppId_t, void* pThis) {
        if (!g_steamEngine) g_steamEngine = pThis;
        const AppId_t real  = oGetAppIDForCurrentPipe(pThis);
        uint32_t      strat = g_cachedStrategy.load(std::memory_order_relaxed);
        // A lobby-browsing client may never send the GetAppID IPC that fills the cache, and would search under its real appid while hosts use 480.
        if (strat == 0 && g_OnlineFixRealAppId) {
            if (uint32_t pid = g_onlineFixPid.load(std::memory_order_relaxed))
                strat = static_cast<uint32_t>(Hooks_Misc::GetAppIdStrategy(pid));
        }
        if (strat == 0) return real;   // no strategy published: untouched

        // Only the game's own pipe, which reports the launch 480, or its real appid once the game re-inits Steam.
        if (real != g_OnlineFixRealAppId && real != kOnlineFixAppId) return real;

        // 480 for every strategy: steamclient licenses the session by this appid, and the real one may be unowned. Only the GetAppID reply differs.
        const AppId_t want = kOnlineFixAppId;
        if (want != real) {
            static std::atomic_bool logged{false};
            if (!logged.exchange(true))
                LOG_MISC_INFO("GetAppIDForCurrentPipe: {} -> {} (strategy={})", real, want, strat);
        }
        return want;
    }


    // ── SpawnProcess interception ────────────────────────────────────────────
    // CUser_SpawnProcess(pCUser, pExePath, pCommandLine, pWorkingDir,
    //                    pGameID, ...)
    // arg1=pCUser, arg2=pExePath, arg3=pCommandLine, arg4=pWorkingDir
    // arg5=pGameID (CGameID*; low 24 bits = AppId)
    static void OnSpawnProcessHit(OSTPlatform::Trap::Context& ctx, const VehCommon::Int3Site& /*site*/) {
        CGameID* pGameID = VehCommon::GetArg<CGameID*>(ctx, 5);
        AppId_t appId = static_cast<AppId_t>(pGameID->AppID(true));
        const char* exePath = VehCommon::GetArg<const char*>(ctx, 2);
        const char* cmdLine = VehCommon::GetArg<const char*>(ctx, 3);

        if (cmdLine && strstr(cmdLine, "-onlinefix"))
        {
            g_OnlineFixRealAppId = appId;
            g_NetworkingSocketsActive = false;
            g_cachedStrategy.store(0, std::memory_order_relaxed);  // re-resolve per game
            g_onlineFixPid.store(0, std::memory_order_relaxed);
            pGameID->SetAppID(kOnlineFixAppId);
            LOG_MISC_INFO("SpawnProcess: appid {} -> {}, cmd=\"{}\"", appId, kOnlineFixAppId, cmdLine);
        } else {
            g_OnlineFixRealAppId = 0;
            g_cachedStrategy.store(0, std::memory_order_relaxed);
            g_onlineFixPid.store(0, std::memory_order_relaxed);
        }
        Hooks_Inject::QueueLaunch(exePath, cmdLine, appId);
    }

    // ── SteamController_OptedInMask ──────────────────────────────────────────
    // Called by CUser_BuildSpawnEnvBlock with pGameID's appid to
    // compute EnableConfiguratorSupport and the SDL_* env vars.
    // With 480 the spawned game inherits Spacewar's Steam Input
    // opt-in and gameoverlayrenderer hijacks the XInput stream.
    HOOK_FUNC(OptedInMask, int64,void* pThis, AppId_t appId)
    {
        if (appId == kOnlineFixAppId && g_OnlineFixRealAppId) {
            LOG_MISC_INFO("OptedInMask: appid {} -> {}",appId, g_OnlineFixRealAppId);
            appId = g_OnlineFixRealAppId;
        }
        return oOptedInMask(pThis, appId);
    }

    // ── CUserFriends::NotifyLobbyJoinRequested ───────────────────────────────
    // Joins go to the running pipes of the invite's appid. The -onlinefix game's pipe is 480, so redirect joins for its real appid.
    HOOK_FUNC(NotifyLobbyJoinRequested, bool, void* pThis, AppId_t appId, uint64 steamIDLobby, uint64 steamIDFriend)
    {
        if (g_OnlineFixRealAppId && appId == g_OnlineFixRealAppId) {
            LOG_MISC_INFO("NotifyLobbyJoinRequested: appid {} -> {}", appId, kOnlineFixAppId);
            appId = kOnlineFixAppId;
        }
        return oNotifyLobbyJoinRequested(pThis, appId, steamIDLobby, steamIDFriend);
    }

    // CUserFriends and its IPC proxy share the IClientFriends vtable layout, and the proxy names its methods.
    void* FindNotifyLobbyJoinRequested()
    {
        void** proxy = PatternLoader::FindVTable(client_hModule, "IClientFriendsMap");
        void** impl  = PatternLoader::FindVTable(client_hModule, "CUserFriends");
        void** slot  = proxy ? PatternLoader::FindVirtualNamed(client_hModule, proxy, "NotifyLobbyJoinRequested") : nullptr;
        if (slot && impl) {
            LOG_MISC_DEBUG("Misc: NotifyLobbyJoinRequested is IClientFriends slot {}", slot - proxy);
            return impl[slot - proxy];
        }
        LOG_WARN("Misc: CUserFriends::NotifyLobbyJoinRequested not found; joins won't reach -onlinefix games");
        return nullptr;
    }

    // ── CUser_BuildSpawnEnvBlock ─────────────────────────────────────────────
    // pOverlayCGameID drives SteamOverlayGameId, which the in-game overlay reads for screenshot tags, community URLs, and asset selection. pCGameID
    // drives SteamGameId / SteamAppId, which the spawned game's steam_api reads to bind its steamclient CONNECTION appid.
    HOOK_FUNC(BuildSpawnEnvBlock, int64,
              void* pThis, CGameID* pCGameID, void* a3, void* env,
              CGameID* pOverlayCGameID, void* a6, int a7,
              void* a8, void* a9, unsigned int a10, char a11)
    {
        // steam_api binds its connection appid from SteamAppId, and the CM only issues the P2P networking cert for an owned appid, so it's 480.
        // The payload reads the real appid from OpenSteamTool_RealAppId_<pid> instead.
        if (g_OnlineFixRealAppId && pCGameID && pCGameID->AppID(true) == g_OnlineFixRealAppId)
        {
            LOG_MISC_INFO("BuildSpawnEnvBlock: SteamAppId env {} -> {} (P2P cert must be 480)", pCGameID->AppID(true), kOnlineFixAppId);
            pCGameID->SetAppID(kOnlineFixAppId);
        }
        if (g_OnlineFixRealAppId && pOverlayCGameID
            && pOverlayCGameID->AppID(true) == kOnlineFixAppId)
        {
            LOG_MISC_INFO("BuildSpawnEnvBlock: SetAppID in OverlayCGameID {} -> {}",
                          pOverlayCGameID->AppID(true), g_OnlineFixRealAppId);
            pOverlayCGameID->SetAppID(g_OnlineFixRealAppId);
        }
        return oBuildSpawnEnvBlock(pThis, pCGameID, a3, env,
                                    pOverlayCGameID, a6, a7,
                                    a8, a9, a10, a11);
    }

    // CAppInfoCache::GetOrAddAppData
    // The injected package keeps Lua-provided ids in PackageInfo::AppIdVec.
    // Some of those ids can actually be depot ids, but we cannot trust the
    // Lua config to classify app ids and depot ids for us. In offline mode,
    // depot ids usually have only placeholder appinfo data. That blocks
    // CClientAppManager_ProcessPendingLicenseUpdates, because it waits for
    // every AppIdVec entry to have resolved appinfo unless the entry has been
    // marked as a known-unknown id by the PICS path. For injected ids that
    // still have placeholder appinfo, set skip_flag so Steam treats them like
    // PICS unknown_appids instead of keeping the license update pending.
    HOOK_FUNC(GetOrAddAppData,CAppData*,void* pCache, AppId_t appId,bool bCreate)
    {
        CAppData* pData = oGetOrAddAppData(pCache, appId, bCreate);
        // LOG_MISC_TRACE("GetOrAddAppData: appId={} bCreate={} -> pData={}", appId, bCreate, pData ? pData->DebugString() : "null");
        // TODO: find a more robust way
        if (LuaConfig::HasDepot(appId, false) && pData && !bCreate && pData->IsUnresolvedAppInfo()) {
            LOG_MISC_DEBUG("GetOrAddAppData: Marking appId {} as skip_flag=true to bypass license update blocking", appId);
            pData->bSkipFlag = true;
        }
        return pData;
    }
}

namespace Hooks_Misc {
    void Install() {
        RESOLVE_C(CUtlBufferEnsureCapacity);

        ARM_CAPTURE_C(GetAppDataFromAppInfo);

        ARM_INT3_C(SpawnProcess, true, &OnSpawnProcessHit, nullptr);

        HOOK_BEGIN();
        INSTALL_HOOK_C(GetAppIDForCurrentPipe);
        INSTALL_HOOK_C(BuildSpawnEnvBlock);
        INSTALL_HOOK_C(OptedInMask);
        INSTALL_HOOK_AT(NotifyLobbyJoinRequested, FindNotifyLobbyJoinRequested());
        // INSTALL_HOOK_C(GetOrAddAppData);
        HOOK_END();
    }

    void Uninstall() {
        UNHOOK_BEGIN();
        UNINSTALL_HOOK(GetAppIDForCurrentPipe);
        UNINSTALL_HOOK(BuildSpawnEnvBlock);
        UNINSTALL_HOOK(OptedInMask);
        UNINSTALL_HOOK(NotifyLobbyJoinRequested);
        // UNINSTALL_HOOK(GetOrAddAppData);
        UNHOOK_END();
    }

    AppId_t GetAppIDForCurrentPipeWrap() {
        if (!g_steamEngine || !oGetAppIDForCurrentPipe) {
            LOG_MISC_WARN("GetAppIDForCurrentPipeWrap called before capture — returning 0");
            return 0;
        }
        auto appid = oGetAppIDForCurrentPipe(g_steamEngine);
        if (!appid) {
            LOG_MISC_TRACE("GetAppIDForCurrentPipeWrap: AppId=0(Not GamePipe)");
        } else {
            LOG_MISC_TRACE("GetAppIDForCurrentPipeWrap: AppId={}", appid);
        }
        return appid;
    }

    
    AppId_t ResolveAppId() {
        if (g_OnlineFixRealAppId) return g_OnlineFixRealAppId;
        return GetAppIDForCurrentPipeWrap();
    }

    bool IsOnlineFixActive() {
        return g_OnlineFixRealAppId != 0;
    }

    void NotifyNetworkingSocketsUsed() {
        if (g_OnlineFixRealAppId && !g_NetworkingSocketsActive) {
            g_NetworkingSocketsActive = true;
            LOG_MISC_INFO("NetworkingSockets active: GetAppID now reports 480 for cert match");
        }
    }

    bool ShouldReportOnlineFixAppId() {
        return g_OnlineFixRealAppId != 0 && g_NetworkingSocketsActive;
    }

    AppIdStrategy GetAppIdStrategy(uint32_t pid) {
        if (!pid) return kStrategyDefault;
        // Cache the view per PID; it keeps the section alive after the game closes its own handle.
        static std::mutex                                    mtx;
        static std::unordered_map<uint32_t, volatile uint32_t*> views;
        std::lock_guard<std::mutex> lock(mtx);
        volatile uint32_t* view = nullptr;
        if (auto it = views.find(pid); it != views.end()) {
            view = it->second;
        } else {
            char name[64];
            sprintf_s(name, "OpenSteamTool_AppIdStrategy_%u", pid);
            if (HANDLE h = OpenFileMappingA(FILE_MAP_READ, FALSE, name)) {
                view = static_cast<volatile uint32_t*>(MapViewOfFile(h, FILE_MAP_READ, 0, 0, sizeof(uint32_t)));
                CloseHandle(h);
                if (view) views[pid] = view;  // cache on success; else retry next call
            }
        }
        const AppIdStrategy s = view ? static_cast<AppIdStrategy>(*view) : kStrategyDefault;
        // Cache a published strategy; SpawnProcess clears it for the next game.
        if (s != kStrategyDefault) g_cachedStrategy.store(static_cast<uint32_t>(s), std::memory_order_relaxed);
        return s;
    }

    void OnGameInjected(uint32_t pid, AppId_t realAppId) {
        if (!pid) return;
        if (g_onlineFixPid.exchange(pid, std::memory_order_relaxed) != pid) LOG_MISC_INFO("OnGameInjected: onlinefix game pid={}", pid);
        if (!realAppId) return;
        // The game's env says 480, so publish its real appid for the payload. The section is leaked so it outlives this handle.
        char name[64];
        sprintf_s(name, "OpenSteamTool_RealAppId_%u", pid);
        if (HANDLE h = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(uint32_t), name))
            if (auto* view = static_cast<uint32_t*>(MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, sizeof(uint32_t))))
                *view = realAppId;
    }

    bool EnsureBufferCapacity(CUtlBuffer* pWrite, uint32 newCapacity,bool updatePut)
    {
        if (oCUtlBufferEnsureCapacity) {
            LOG_MISC_DEBUG("Before ensuring CUtlBuffer capacity: {}", pWrite->DebugString());
            oCUtlBufferEnsureCapacity(pWrite, newCapacity);
            LOG_MISC_DEBUG("After ensuring CUtlBuffer capacity: {}", pWrite->DebugString());
            if(updatePut) pWrite->m_Put = newCapacity;
            return true;
        }
        LOG_MISC_WARN("EnsureBufferCapacity: oCUtlBufferEnsureCapacity not resolved");
        return false;
    }

    // ── Game name ────────────────────────────────────────────────
    std::string GetGameNameByAppID(AppId_t appId)
    {
        auto it = g_GameNameCache.find(appId);
        if (it != g_GameNameCache.end()) return it->second;

        std::string name;

        if (CAPTURE_READY(GetAppDataFromAppInfo)) {
            char buf[256] = {};
            // "common/name" triggers auto-localization: the function detects
            // prefix "common" (keyType=2) + key "name", then tries
            // "name_localized/<current_lang>" before falling back to "name".
            // Returns strlen+1 on success, -1 on failure.
            int64 len = oGetAppDataFromAppInfo(g_pCAppInfoCache, appId, "common/name",
                reinterpret_cast<uint8*>(buf), sizeof(buf));
            if (len > 1)
                name.assign(buf, static_cast<size_t>(len - 1));
        }

        LOG_MISC_DEBUG("GetGameNameByAppID({}): {}", appId, name);
        g_GameNameCache[appId] = name;
        return name;
    }

}

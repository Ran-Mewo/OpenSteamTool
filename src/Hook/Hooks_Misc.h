#pragma once

#include "dllmain.h"

// Catch-all for lightweight info-capture int3 traps and launch-time rewrites
// that don't fit a dedicated category — currently:
//   * GetAppIDForCurrentPipe  -> hook: reports 480 once a payload publishes a strategy; also captures the SteamEngine pointer
//   * SpawnProcess            -> -onlinefix detection + 480 rewrite; queues the launch for [[inject]]
//   * GetAppDataFromAppInfo   -> captures the CAppInfoCache pointer
namespace Hooks_Misc {
    void Install();
    void Uninstall();

    // Returns the AppId for the current Steam pipe via the captured engine
    // pointer, or 0 if we haven't yet observed the host calling
    // GetAppIDForCurrentPipe.
    AppId_t GetAppIDForCurrentPipeWrap();

    // True while a -onlinefix game is the active spawn.
    bool IsOnlineFixActive();

    // Call when the game uses SteamNetworkingSockets (IPC interface 46).
    void NotifyNetworkingSocketsUsed();

    // True once P2P started — GetAppID reports 480; before, the real appid.
    bool ShouldReportOnlineFixAppId();

    // The strategy an injected payload published in the shared block "OpenSteamTool_AppIdStrategy_<pid>"; Default keeps the P2P flip.
    enum AppIdStrategy : uint32_t {
        kStrategyDefault   = 0,
        kStrategyForce480  = 1,
        kStrategyForceReal = 2,
    };
    AppIdStrategy GetAppIdStrategy(uint32_t pid);

    // Record an injected game's PID and publish its real appid for the payload.
    void OnGameInjected(uint32_t pid, AppId_t realAppId);

    // Grow a CUtlBuffer to at least 'newCapacity' bytes and set m_Put = newCapacity.
    // Uses CUtlBuffer::EnsureCapacity from steamclient, resolved on first call.
    bool EnsureBufferCapacity(CUtlBuffer* pWrite, uint32 newCapacity,bool updatePut = false);

    // Resolve the real appid: if OnlineFix is active return real appid,
    // otherwise fall back to GetAppIDForCurrentPipe().
    AppId_t ResolveAppId();

    // Get localized game name via GetAppDataFromAppInfo (cached).
    std::string GetGameNameByAppID(AppId_t appId);

}

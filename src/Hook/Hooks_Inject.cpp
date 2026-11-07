#include "Hooks_Inject.h"
#include "HookMacros.h"
#include "Pipe/Features/Injection/Injection.h"
#include "Utils/Config/Config.h"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace {

    // Launches SpawnProcess saw, by lowercased exe basename: Steam calls CreateProcessW on another thread, so the name is all that ties them.
    struct Launch {
        AppId_t     appId = 0;
        std::string cmdLine;
    };
    std::mutex g_pendingMutex;
    std::unordered_map<std::wstring, Launch> g_pending;

    std::wstring LowerBasename(LPCWSTR path) {
        if (!path || !*path) return {};
        std::wstring name = std::filesystem::path(path).filename().wstring();
        std::transform(name.begin(), name.end(), name.begin(),
            [](wchar_t c){ return static_cast<wchar_t>(towlower(c)); });
        return name;
    }

    // lpApplicationName is often null and the exe is the first token of
    // lpCommandLine instead. Peel it off (quoted or unquoted) so we can
    // still derive a basename in that case.
    std::wstring ExeFromCmd(LPCWSTR cmd) {
        if (!cmd) return {};
        while (*cmd == L' ' || *cmd == L'\t') ++cmd;
        std::wstring out;
        if (*cmd == L'"') {
            for (++cmd; *cmd && *cmd != L'"'; ++cmd) out.push_back(*cmd);
        } else {
            for (; *cmd && *cmd != L' ' && *cmd != L'\t'; ++cmd) out.push_back(*cmd);
        }
        return out;
    }

    std::optional<Launch> ClaimPending(LPCWSTR app, LPCWSTR cmd) {
        std::wstring key = LowerBasename(app);
        if (key.empty()) key = LowerBasename(ExeFromCmd(cmd).c_str());
        std::lock_guard lk(g_pendingMutex);
        auto it = g_pending.find(key);
        if (it == g_pending.end()) return std::nullopt;
        Launch launch = std::move(it->second);
        g_pending.erase(it);
        return launch;
    }

    // ── CreateProcessW / CreateProcessAsUserW hooks ────────────────────
    using CreateProcessW_t = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
        LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
        LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    using CreateProcessAsUserW_t = BOOL(WINAPI*)(HANDLE, LPCWSTR, LPWSTR,
        LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
        LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

    CreateProcessW_t       oCreateProcessW       = nullptr;
    CreateProcessAsUserW_t oCreateProcessAsUserW = nullptr;

    BOOL Spawn(HANDLE token, LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
               LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env,
               LPCWSTR cwd, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
    {
        auto fwd = [&](DWORD f) {
            return token
                ? oCreateProcessAsUserW(token, app, cmd, pa, ta, inherit, f, env, cwd, si, pi)
                : oCreateProcessW(app, cmd, pa, ta, inherit, f, env, cwd, si, pi);
        };

        const std::optional<Launch> launch = ClaimPending(app, cmd);
        if (!launch || Config::injectDlls.empty()) return fwd(flags);

        // Start suspended so the DLLs load before the game's first instruction, then resume unless the caller already wanted it held.
        BOOL ok = fwd(flags | CREATE_SUSPENDED);
        if (!ok) return ok;
        PipeManager::Injection::OnLaunch(pi->hProcess, pi->dwProcessId, launch->appId, launch->cmdLine);
        if (!(flags & CREATE_SUSPENDED)) ResumeThread(pi->hThread);
        return ok;
    }

    BOOL WINAPI hkCreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
        LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env,
        LPCWSTR cwd, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
    {
        return Spawn(nullptr, app, cmd, pa, ta, inherit, flags, env, cwd, si, pi);
    }

    BOOL WINAPI hkCreateProcessAsUserW(HANDLE token, LPCWSTR app, LPWSTR cmd,
        LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags,
        LPVOID env, LPCWSTR cwd, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
    {
        return Spawn(token, app, cmd, pa, ta, inherit, flags, env, cwd, si, pi);
    }
}

namespace Hooks_Inject {
    void Install() {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        if (!k32) return;
        oCreateProcessW       = reinterpret_cast<CreateProcessW_t>      (GetProcAddress(k32, "CreateProcessW"));
        oCreateProcessAsUserW = reinterpret_cast<CreateProcessAsUserW_t>(GetProcAddress(k32, "CreateProcessAsUserW"));

        HOOK_BEGIN();
        if (oCreateProcessW)
            OSTPlatform::Detour::Attach(reinterpret_cast<void**>(&oCreateProcessW), reinterpret_cast<void*>(hkCreateProcessW));
        if (oCreateProcessAsUserW)
            OSTPlatform::Detour::Attach(reinterpret_cast<void**>(&oCreateProcessAsUserW), reinterpret_cast<void*>(hkCreateProcessAsUserW));
        HOOK_END();
    }

    void Uninstall() {
        UNHOOK_BEGIN();
        if (oCreateProcessW) {
            OSTPlatform::Detour::Detach(reinterpret_cast<void**>(&oCreateProcessW), reinterpret_cast<void*>(hkCreateProcessW));
            oCreateProcessW = nullptr;
        }
        if (oCreateProcessAsUserW) {
            OSTPlatform::Detour::Detach(reinterpret_cast<void**>(&oCreateProcessAsUserW), reinterpret_cast<void*>(hkCreateProcessAsUserW));
            oCreateProcessAsUserW = nullptr;
        }
        UNHOOK_END();

        std::lock_guard lk(g_pendingMutex);
        g_pending.clear();
    }

    void QueueLaunch(const char* exePath, const char* cmdLine, AppId_t appId) {
        if (!appId || !exePath || !*exePath) return;
        wchar_t wexe[MAX_PATH] = {};
        MultiByteToWideChar(CP_UTF8, 0, exePath, -1, wexe, MAX_PATH);
        const std::wstring key = LowerBasename(wexe);
        if (key.empty()) return;
        std::lock_guard lk(g_pendingMutex);
        g_pending[key] = { appId, cmdLine ? cmdLine : "" };
    }
}

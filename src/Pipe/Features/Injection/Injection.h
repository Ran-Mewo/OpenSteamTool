#pragma once

#include "Pipe/PipeTypes.h"

#include <string>
#include <windows.h>

namespace PipeManager::Injection {

    // Steam is starting the game appId with cmdLine as `process`, still suspended: inject the matching [[inject]] DLLs before its first instruction.
    void OnLaunch(HANDLE process, uint32_t pid, AppId_t appId, const std::string& cmdLine);

    // A process connected to Steam: inject the [[inject]] DLLs that match it, or that matched the launch it belongs to.
    void Apply(const PipeContext& ctx);

} // namespace PipeManager::Injection

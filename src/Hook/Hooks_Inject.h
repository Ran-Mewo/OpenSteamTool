#pragma once

#include "dllmain.h"

namespace Hooks_Inject {
    void Install();
    void Uninstall();

    // Steam is about to start exePath for appId: inject the matching [[inject]] DLLs at launch, before the game's first instruction.
    void QueueLaunch(const char* exePath, const char* cmdLine, AppId_t appId);
}

#pragma once

#include "OSTPlatform/include/DynamicLibrary.h"

#include <string>

namespace PatternLoader {

    // Load metadata before installing hooks for a module.
    bool Load(OSTPlatform::DynamicLibrary::ModuleHandle module, const std::string& dllPath, const std::string& component);

    // Resolve by RVA first, then fall back to signature scanning.
    void* FindPattern(OSTPlatform::DynamicLibrary::ModuleHandle module, const char* funcName);

    // Primary vtable of an MSVC class, found through its RTTI name.
    void** FindVTable(OSTPlatform::DynamicLibrary::ModuleHandle module, const char* className);

    // Vtable slot whose virtual loads target (rip-relative lea).
    void** FindVirtualReferencing(OSTPlatform::DynamicLibrary::ModuleHandle module, void** vtable, const void* target);

    // Vtable slot whose virtual loads the string name. IPC proxies (IClient*Map) load the names of their methods.
    void** FindVirtualNamed(OSTPlatform::DynamicLibrary::ModuleHandle module, void** vtable, const char* name);

    // Report unresolved functions after all hooks have been installed.
    void ReportMissingFunctions();

} // namespace PatternLoader

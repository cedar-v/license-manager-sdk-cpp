// MinGW WinLibs UCRT compatibility shim
// Some MinGW distributions (notably WinLibs with UCRT) ship a libstdc++ that
// references at_quick_exit/quick_exit/timespec_get in its <cstdlib>/<ctime>
// headers, but the bundled UCRT C library does not provide them.  This file
// declares those symbols in the global namespace BEFORE any standard header
// is included, so the `using ::` declarations in the libstdc++ headers find
// a valid declaration.
//
// This file has no effect on MSVC or non-MinGW toolchains.
#pragma once

#if defined(__MINGW32__) || defined(__MINGW64__)

extern "C" {
    int at_quick_exit(void (*func)(void)) noexcept;
    [[noreturn]] void quick_exit(int status) noexcept;
    int timespec_get(struct timespec*, int) noexcept;
}

#endif

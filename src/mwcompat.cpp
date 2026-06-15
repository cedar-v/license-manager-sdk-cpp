// MinGW WinLibs UCRT compatibility stubs.
// Provides link-time implementations of at_quick_exit/quick_exit/timespec_get
// for MinGW UCRT toolchains that declare but do not implement these symbols.
#if defined(__MINGW32__) || defined(__MINGW64__)

#include <cstdlib>
#include <ctime>
#include <time.h>

extern "C" int at_quick_exit(void (*)(void)) noexcept { return 0; }
extern "C" [[noreturn]] void quick_exit(int status) noexcept { std::exit(status); }
extern "C" int timespec_get(struct timespec* ts, int base) noexcept {
    // On MinGW TIME_UTC may not be visible; the C standard requires this value == 1.
    if (base == 1 && ts != nullptr) {
        ts->tv_sec = static_cast<time_t>(std::time(nullptr));
        ts->tv_nsec = 0;
        return base;
    }
    return 0;
}

#endif

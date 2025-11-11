
// Cross-platform timer implementation:
// - Windows: Query Performance Counter
// - POSIX: gettimeofday / clock_gettime
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <timer.h>

#if defined(_WIN32)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>

    static inline double qpc_usecs() {
        static LARGE_INTEGER freq = {0};
        static BOOL have = QueryPerformanceFrequency(&freq);
        (void)have;
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        return (double)now.QuadPart * 1000000.0 / (double)freq.QuadPart;
    }

    static inline uint64_t qpc_nanos() {
        static LARGE_INTEGER freq = {0};
        static BOOL have = QueryPerformanceFrequency(&freq);
        (void)have;
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        // scale to nanoseconds without overflow
        return (uint64_t)((now.QuadPart * 1000000000.0) / (double)freq.QuadPart);
    }
#else
    #include <sys/time.h>
#endif

double Timer::usecs() {
#if defined(_WIN32)
    return qpc_usecs();
#else
    struct timeval t;
    gettimeofday(&t, 0);
    return t.tv_usec + 1000000.0 * ((double)t.tv_sec);
#endif
}

uint64_t Timer::nanos() {
#if defined(_WIN32)
    return qpc_nanos();
#elif defined(linux)
    struct timespec t;
    int r = clock_gettime(CLOCK_MONOTONIC_RAW, &t);
    if(r<0) {
        perror("clock_gettime");
        return (uint64_t)-1;
    }
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
#else
    return (uint64_t)(1000.0 * usecs());
#endif
}


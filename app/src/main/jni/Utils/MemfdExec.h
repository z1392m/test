// Utils/MemfdExec.h
// Drop-in memfd trampoline pool for SDK 36 W^X — replaces Dobby's anonymous mmap.
// Call InitTrampolinePool() once before any DobbyHook().
// NDK r25c+, minSdkVersion 29 (memfd_create via syscall fallback for API 29).
//
// FILL: adjust TRAMPOLINE_POOL_SIZE = expected hook count x 64 bytes.

#pragma once
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <errno.h>

#define KXMODS_TRAMPOLINE_TAG  "KXMODS_TRAMPOLINEALLOC"
#define TRAMPOLINE_POOL_SIZE   (64 * 64)   // 64 hooks x 64 bytes each

static int    g_memfd      = -1;
static void*  g_pool_rx    = nullptr;
static void*  g_pool_rw    = nullptr;
static size_t g_pool_used  = 0;

inline int InitTrampolinePool() {
    if (g_pool_rx != nullptr) return 0;

    int fd = (int)syscall(__NR_memfd_create, "kxmods_tramp",
                          MFD_CLOEXEC | MFD_EXEC);
    if (fd < 0) {
        fd = (int)syscall(__NR_memfd_create, "kxmods_tramp",
                          MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (fd < 0) {
            __android_log_print(ANDROID_LOG_ERROR, KXMODS_TRAMPOLINE_TAG,
                "memfd_create failed errno=%d", errno);
            return -1;
        }
        fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW);
    }

    if (ftruncate(fd, TRAMPOLINE_POOL_SIZE) < 0) {
        close(fd); return -1;
    }

    void* rw = mmap(nullptr, TRAMPOLINE_POOL_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, 0);
    if (rw == MAP_FAILED) { close(fd); return -1; }

    void* rx = mmap(nullptr, TRAMPOLINE_POOL_SIZE, PROT_READ | PROT_EXEC,
                    MAP_SHARED, fd, 0);
    if (rx == MAP_FAILED) {
        munmap(rw, TRAMPOLINE_POOL_SIZE); close(fd); return -1;
    }

    g_memfd   = fd;
    g_pool_rw = rw;
    g_pool_rx = rx;
    g_pool_used = 0;

    __android_log_print(ANDROID_LOG_INFO, KXMODS_TRAMPOLINE_TAG,
        "Trampoline pool ready: RW=%p RX=%p size=%d",
        rw, rx, (int)TRAMPOLINE_POOL_SIZE);
    return 0;
}

inline int SafeMprotect(void* addr, size_t len, int prot) {
    int rc = mprotect(addr, len, prot);
    if (rc != 0) {
        __android_log_print(ANDROID_LOG_FATAL, "KXMODS_HOOK",
            "mprotect(%p, %zu, 0x%x) FAILED errno=%d — W^X on SDK 36",
            addr, len, prot, errno);
        abort();
    }
    return rc;
}

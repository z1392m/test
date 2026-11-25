#pragma once
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <errno.h>
#include <string.h>

#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#define KXMODS_TRAMPOLINE_TAG  "KXMODS_TRAMPOLINEALLOC"
#define TRAMPOLINE_POOL_SIZE   (64 * 64)

static void*  g_pool_rx    = nullptr;
static void*  g_pool_rw    = nullptr;

// Try memfd_create (blocked on some targets by seccomp).
static int try_memfd() {
    int fd = (int)syscall(__NR_memfd_create, "kxmods_tramp",
                          MFD_CLOEXEC | MFD_EXEC);
    if (fd < 0)
        fd = (int)syscall(__NR_memfd_create, "kxmods_tramp",
                          MFD_CLOEXEC | MFD_ALLOW_SEALING);
    return fd;
}

// Fallback: ashmem — always whitelisted, file-backed, supports RX mapping.
static int try_ashmem() {
    int fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    // Use ioctl ASHMEM_SET_SIZE = 0x40087703
    struct { const char* name; unsigned long size; } req = {nullptr, (unsigned long)TRAMPOLINE_POOL_SIZE};
    // Simpler: just ftruncate won't work on ashmem; use the size ioctl.
    // ioctl number: _IOW(0x77, 3, size_t) = 0x40087703 on 64-bit
    if (syscall(__NR_ioctl, fd, 0x40087703ul, (unsigned long)TRAMPOLINE_POOL_SIZE) < 0) {
        close(fd); return -1;
    }
    return fd;
}

inline int InitTrampolinePool() {
    if (g_pool_rx != nullptr) return 0;

    int fd = try_memfd();
    bool is_memfd = (fd >= 0);

    if (!is_memfd) {
        __android_log_print(ANDROID_LOG_WARN, KXMODS_TRAMPOLINE_TAG,
            "memfd_create blocked (seccomp/EPERM errno=%d), trying ashmem", errno);
        fd = try_ashmem();
        if (fd < 0) {
            __android_log_print(ANDROID_LOG_ERROR, KXMODS_TRAMPOLINE_TAG,
                "ashmem also failed errno=%d — no exec pool available", errno);
            return -1;
        }
    } else {
        if (ftruncate(fd, TRAMPOLINE_POOL_SIZE) < 0) {
            close(fd); return -1;
        }
    }

    void* rw = mmap(nullptr, TRAMPOLINE_POOL_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, 0);
    if (rw == MAP_FAILED) {
        close(fd); return -1;
    }

    void* rx = mmap(nullptr, TRAMPOLINE_POOL_SIZE, PROT_READ | PROT_EXEC,
                    MAP_SHARED, fd, 0);
    if (rx == MAP_FAILED) {
        munmap(rw, TRAMPOLINE_POOL_SIZE);
        close(fd); return -1;
    }

    g_pool_rw = rw;
    g_pool_rx = rx;
    close(fd); // mappings keep the fd alive internally

    __android_log_print(ANDROID_LOG_INFO, KXMODS_TRAMPOLINE_TAG,
        "Pool ready via %s: RW=%p RX=%p",
        is_memfd ? "memfd" : "ashmem", rw, rx);
    return 0;
}

inline int SafeMprotect(void* addr, size_t len, int prot) {
    int rc = mprotect(addr, len, prot);
    if (rc != 0) {
        __android_log_print(ANDROID_LOG_FATAL, "KXMODS_HOOK",
            "mprotect(%p, %zu, 0x%x) FAILED errno=%d — W^X SDK 36",
            addr, len, prot, errno);
        abort();
    }
    return rc;
}

/* The one POSIX call upstream's S3 host tests make (test_hal.c: a page of
 * memory below 4 GiB, so the target's 32-bit pointer fields keep their
 * offsets), on Windows: VirtualAlloc at the first free address from 256 MiB
 * up. E1's addition beside the unchanged upstream files; MIT OR Apache-2.0. */
#ifndef JANUS_WIN_SYS_MMAN_H
#define JANUS_WIN_SYS_MMAN_H
#include <stddef.h>
#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MAP_32BIT 0x40
#define MAP_FAILED ((void *)-1)

static void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset)
{
    (void)addr; (void)prot; (void)flags; (void)fd; (void)offset;
    for (uintptr_t at = 0x10000000u; at < 0xF0000000u; at += 0x10000u) {
        void *p = VirtualAlloc((void *)at, length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (p) return p;
    }
    return MAP_FAILED;
}

static int munmap(void *addr, size_t length)
{
    (void)length;
    return VirtualFree(addr, 0, MEM_RELEASE) ? 0 : -1;
}
#endif

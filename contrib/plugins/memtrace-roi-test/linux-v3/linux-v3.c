/* Targeted x86-64 Linux v3 capture workload. SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#if !defined(__linux__) || !defined(__x86_64__)
#error "linux-v3 requires x86-64 Linux"
#endif
#define BEGIN() __asm__ volatile ( \
    ".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x42,0x47" ::: "memory")
#define END() __asm__ volatile ( \
    ".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x45,0x4e" ::: "memory")
extern const unsigned char linux_v3_wide_load_pc[], linux_v3_wide_store_pc[];
extern const unsigned char linux_v3_old_pc[], linux_v3_new_pc[];

__attribute__((noinline,noclone))
static void wide_load(const void *source, void *result)
{
    __asm__ volatile (
        ".globl linux_v3_wide_load_pc\nlinux_v3_wide_load_pc:\n"
        "movdqu (%[source]), %%xmm0\n"
        "movdqu %%xmm0, (%[result])\n"
        : : [source] "r" (source), [result] "r" (result) : "xmm0", "memory");
}
__attribute__((noinline,noclone))
static void wide_store(void *destination, const void *value)
{
    __asm__ volatile (
        "movdqu (%[value]), %%xmm1\n"
        ".globl linux_v3_wide_store_pc\nlinux_v3_wide_store_pc:\n"
        "movdqu %%xmm1, (%[destination])\n"
        : : [destination] "r" (destination), [value] "r" (value) : "xmm1", "memory");
}

int main(int argc, char **argv)
{
    unsigned char *cross = MAP_FAILED, *backing = MAP_FAILED;
    void *slot = MAP_FAILED, *mapped;
    unsigned char expected[16], replacement[16], loaded[16] = {0};
    unsigned old_value = 0, new_value = 0;
    int fd = -1, active = 0, failed = 0, saved_errno = 0;
    const char *failure = NULL;
    (void)argv;
    if (argc != 1) { fprintf(stderr,"linux-v3: no arguments accepted\n"); return 1; }
    long page_size=sysconf(_SC_PAGESIZE);
    if (page_size<0) { perror("linux-v3: sysconf"); return 1; }
    if (page_size != 4096) {
        fprintf(stderr,"linux-v3: requires 4096-byte OS pages\n"); return 1;
    }
#define CHECK(test, name) do { if (!(test)) { failure=(name); saved_errno=errno; goto cleanup; } } while (0)
    cross = mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(cross != MAP_FAILED,"cross mmap");
    CHECK(madvise(cross,8192,MADV_NOHUGEPAGE)==0,"cross MADV_NOHUGEPAGE");
    /* Populate both pages, then set the boundary's initial bytes before BEGIN. */
    memset(cross,0x19,8192);
    for (unsigned i=0;i<16;i++) { expected[i]=(unsigned char)(0x20+i); replacement[i]=(unsigned char)(0xc0+i); }
    memcpy(cross+4088,expected,16);

    fd = memfd_create("memtrace-linux-v3",MFD_CLOEXEC);
    CHECK(fd >= 0,"memfd_create");
    CHECK(ftruncate(fd,8192)==0,"ftruncate");
    backing = mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    CHECK(backing != MAP_FAILED,"backing mmap");
    CHECK(madvise(backing,8192,MADV_NOHUGEPAGE)==0,"backing MADV_NOHUGEPAGE");
    memset(backing,0x31,4096); memset(backing+4096,0xa7,4096);
    slot = mmap(NULL,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(slot != MAP_FAILED,"reserve mmap");
    /* Both MAP_FIXED calls replace exactly this still-owned one-page slot.
     * No unmap-before-remap gap, arbitrary VA, or unrelated mapping is used. */
    mapped = mmap(slot,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,fd,0);
    CHECK(mapped != MAP_FAILED,"map page A");
    CHECK(madvise(slot,4096,MADV_NOHUGEPAGE)==0,"page A MADV_NOHUGEPAGE");
    CHECK(printf("linux_v3_test=1\npage_size=4096\n"
                 "cross_base=0x%" PRIxPTR "\ncross_va=0x%" PRIxPTR "\n"
                 "cross_load_pc=0x%" PRIxPTR "\ncross_store_pc=0x%" PRIxPTR "\n"
                 "remap_va=0x%" PRIxPTR "\nremap_old_pc=0x%" PRIxPTR "\nremap_new_pc=0x%" PRIxPTR "\n",
                 (uintptr_t)cross,(uintptr_t)(cross+4088),
                 (uintptr_t)linux_v3_wide_load_pc,(uintptr_t)linux_v3_wide_store_pc,
                 (uintptr_t)slot,(uintptr_t)linux_v3_old_pc,(uintptr_t)linux_v3_new_pc)>=0 &&
          fflush(stdout)==0,"preparation report");

    active=1; BEGIN();
    wide_load(cross+4088,loaded);
    wide_store(cross+4088,replacement);
    END(); active=0;
    if (memcmp(loaded,expected,16) || memcmp(cross+4088,replacement,16)) {
        failure="cross-page byte verification"; saved_errno=0; goto cleanup;
    }
    CHECK(puts("cross_verified=1")!=EOF && fflush(stdout)==0,"cross report");

    active=1; BEGIN();
    __asm__ volatile (
        ".globl linux_v3_old_pc\nlinux_v3_old_pc:\nmovzbl (%1), %0"
        : "=r" (old_value) : "r" (slot) : "memory");
    mapped = mmap(slot,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,fd,4096);
    CHECK(mapped != MAP_FAILED,"replace with page B inside ROI");
    CHECK(madvise(slot,4096,MADV_NOHUGEPAGE)==0,"page B MADV_NOHUGEPAGE inside ROI");
    __asm__ volatile (
        ".globl linux_v3_new_pc\nlinux_v3_new_pc:\nmovzbl (%1), %0"
        : "=r" (new_value) : "r" (slot) : "memory");
    END(); active=0;
    if (old_value!=0x31 || new_value!=0xa7) {
        failure="old/new mapped byte verification"; saved_errno=0; goto cleanup;
    }
    /* Check MAP_SHARED aliasing and both complete backing pages outside ROI. */
    *(volatile unsigned char *)slot=0x5c;
    for (unsigned i=0;i<4096;i++) {
        if (backing[i]!=0x31 || backing[4096+i]!=(i ? 0xa7 : 0x5c)) {
            failure="backing page/alias verification"; saved_errno=0; goto cleanup;
        }
    }
    CHECK(printf("remap_old_value=%u\nremap_new_value=%u\nremap_verified=1\n",
                 old_value,new_value)>=0 && fflush(stdout)==0,"remap report");
cleanup:
    if (active) { END(); active=0; } /* Recoverable syscall failure closes ROI. */
    if (failure) {
        fprintf(stderr,"linux-v3: %s%s%s\n",failure,saved_errno?": ":"",
                saved_errno?strerror(saved_errno):""); failed=1;
    }
    if (slot!=MAP_FAILED && munmap(slot,4096)) { perror("linux-v3: unmap slot"); failed=1; }
    if (backing!=MAP_FAILED && munmap(backing,8192)) { perror("linux-v3: unmap backing"); failed=1; }
    if (fd>=0 && close(fd)) { perror("linux-v3: close memfd"); failed=1; }
    if (cross!=MAP_FAILED && munmap(cross,8192)) { perror("linux-v3: unmap cross"); failed=1; }
    if (!failed && (puts("linux_v3_success=1")==EOF || fflush(stdout))) { perror("linux-v3: final report"); failed=1; }
    return failed;
}

/* Standalone x86-64 Linux test. SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "first-touch requires x86-64 Linux"
#endif

#define BEGIN() __asm__ volatile ( \
    ".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x42,0x47" ::: "memory")
#define END() __asm__ volatile ( \
    ".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x45,0x4e" ::: "memory")

int main(void)
{
    const size_t page_count = 16;
    long page_size_result = sysconf(_SC_PAGESIZE);
    size_t page_size, length;
    volatile unsigned char *pages;
    void *mapping;
    int failed = 0;

    if (page_size_result <= 0) {
        fprintf(stderr, "first-touch: could not obtain page size\n");
        return 1;
    }
    page_size = (size_t)page_size_result;
    if (page_size > SIZE_MAX / page_count) {
        fprintf(stderr, "first-touch: mapping size overflow\n");
        return 1;
    }
    length = page_size * page_count;
    mapping = mmap(NULL, length, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("first-touch: mmap");
        return 1;
    }
    if (madvise(mapping, length, MADV_NOHUGEPAGE) != 0) {
        perror("first-touch: madvise(MADV_NOHUGEPAGE)");
        failed = 1;
        goto cleanup;
    }

    /* Reporting the pointer does not access the mapped memory. All program
     * output occurs outside markers and is separate from the host CSV.
     */
    if (printf("base=0x%" PRIxPTR " page_size=%zu page_count=%zu\n",
               (uintptr_t)mapping, page_size, page_count) < 0 ||
        fflush(stdout) != 0) {
        perror("first-touch: mapping report");
        failed = 1;
        goto cleanup;
    }
    pages = mapping;

    BEGIN();
    for (size_t i = 0; i < page_count; i++) {
        pages[i * page_size] = 1;
    }
    END();

    if (puts("completed first-touch pass") == EOF || fflush(stdout) != 0) {
        perror("first-touch: pass report");
        failed = 1;
        goto cleanup;
    }

    BEGIN();
    for (size_t i = 0; i < page_count; i++) {
        pages[i * page_size] = 2;
    }
    END();

    if (puts("completed resident pass") == EOF || fflush(stdout) != 0) {
        perror("first-touch: pass report");
        failed = 1;
    }

cleanup:
    if (munmap(mapping, length) != 0) {
        perror("first-touch: munmap");
        failed = 1;
    }
    return failed;
}

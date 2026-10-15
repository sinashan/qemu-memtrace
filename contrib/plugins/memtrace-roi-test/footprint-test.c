/* Controlled resident-page reads. SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "footprint-test requires x86-64 Linux"
#endif
#define BEGIN() __asm__ volatile ( \
    ".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x42,0x47" ::: "memory")
#define END() __asm__ volatile ( \
    ".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x45,0x4e" ::: "memory")

static int positive(const char *s, uint64_t *value)
{
    uint64_t n = 0;
    if (!*s) return 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || n > (UINT64_MAX - (*s - '0')) / 10)
            return 0;
        n = n * 10 + (*s - '0');
    }
    *value = n;
    return n != 0;
}

int main(int argc, char **argv)
{
    uint64_t count = 32, passes = 4, expected, checksum = 0, per_pass = 0;
    unsigned seen = 0;
    int permuted = 0, failed = 0;
    for (int i = 1; i < argc; i++) {
        unsigned flag;
        if (!strcmp(argv[i], "--pages")) flag = 1;
        else if (!strcmp(argv[i], "--passes")) flag = 2;
        else if (!strcmp(argv[i], "--pattern")) flag = 4;
        else {
            fprintf(stderr, "footprint-test: unknown option %s\n", argv[i]);
            return 1;
        }
        if ((seen & flag) || i + 1 == argc) {
            fprintf(stderr, "footprint-test: duplicate option or missing value: %s\n", argv[i]);
            return 1;
        }
        seen |= flag;
        const char *value = argv[++i];
        if (flag == 4) {
            if (!strcmp(value, "permuted")) permuted = 1;
            else if (strcmp(value, "sequential")) {
                fprintf(stderr, "footprint-test: pattern must be sequential or permuted\n");
                return 1;
            }
        } else if (!positive(value, flag == 1 ? &count : &passes)) {
            fprintf(stderr, "footprint-test: expected a positive decimal integer: %s\n", value);
            return 1;
        }
    }
    /* Limit mapping to 256 MiB and bound arithmetic and experiment duration. */
    if (count > 65536 || (count & (count - 1)) || passes > 1000000 ||
        count > UINT64_MAX / passes || count * passes > UINT64_MAX / 255) {
        fprintf(stderr, "footprint-test: pages must be a power of two in [1,65536]; passes in [1,1000000]\n");
        return 1;
    }
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size != 4096 || count > SIZE_MAX / 4096) {
        fprintf(stderr, "footprint-test: requires 4096-byte OS pages and a representable mapping\n");
        return 1;
    }
    size_t length = (size_t)count * 4096;
    expected = count * passes;
    /* Half the footprint plus one page: odd for powers of two >= 4.
     * For 32/512/4096 pages this gives strides 17/257/2049 respectively.
     * Odd multiplication modulo a power of two is a bijection. Products
     * fit uint64_t under the checked page bound. No permutation array.
     */
    uint64_t stride = permuted && count >= 4 ? count / 2 + 1 : 1;
    void *mapping = mmap(NULL, length, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) { perror("footprint-test: mmap"); return 1; }
    if (madvise(mapping, length, MADV_NOHUGEPAGE)) {
        perror("footprint-test: madvise(MADV_NOHUGEPAGE)");
        failed = 1;
        goto cleanup;
    }
    volatile unsigned char *pages = mapping;
    /* Populate all translations outside the global recording interval. */
    for (uint64_t i = 0; i < count; i++) {
        unsigned char value = (unsigned char)(i % 251 + 1);
        pages[i * 4096] = value;
        per_pass += value;
    }
    if (printf("base=0x%" PRIxPTR " page_size=%ld page_count=%" PRIu64
               " footprint_bytes=%zu passes=%" PRIu64 " pattern=%s stride=%" PRIu64
               " expected_page_start_reads=%" PRIu64 "\n", (uintptr_t)mapping,
               page_size, count, length, passes, permuted ? "permuted" : "sequential",
               stride, expected) < 0 || fflush(stdout)) {
        perror("footprint-test: mapping report"); failed = 1; goto cleanup;
    }
    /* Global ROI can still contain compiler/stack accesses, interrupts and
     * kernel/other-process accesses. There are no explicit syscalls here.
     */
    BEGIN();
    for (uint64_t pass = 0; pass < passes; pass++) {
        for (uint64_t i = 0; i < count; i++) {
            uint64_t index = (i * stride) & (count - 1);
            checksum += pages[index * 4096];
        }
    }
    END();
    if (printf("checksum=%" PRIu64 " expected_checksum=%" PRIu64 "\n",
               checksum, per_pass * passes) < 0 || fflush(stdout)) {
        perror("footprint-test: checksum report"); failed = 1;
    }
    if (checksum != per_pass * passes) {
        fprintf(stderr, "footprint-test: checksum mismatch\n"); failed = 1;
    }
cleanup:
    if (munmap(mapping, length)) { perror("footprint-test: munmap"); failed = 1; }
    return failed;
}

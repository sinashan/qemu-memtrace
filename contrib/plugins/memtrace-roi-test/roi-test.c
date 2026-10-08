/* Standalone x86-64 guest test. SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define BEGIN() __asm__ volatile ( \
    ".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x42,0x47" ::: "memory")
#define END() __asm__ volatile ( \
    ".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x45,0x4e" ::: "memory")

int main(void)
{
    /* Separate regions allow verification without assuming instruction PCs
     * or compiler-generated stack access counts. stdout is separate from CSV.
     */
    volatile uint64_t *array = calloc(24, sizeof(uint64_t));
    if (!array) {
        return 1;
    }
    printf("pre=0x%lx active=0x%lx post=0x%lx bytes=%zu\n",
           (unsigned long)(uintptr_t)array,
           (unsigned long)(uintptr_t)(array + 8),
           (unsigned long)(uintptr_t)(array + 16), 8 * sizeof(*array));
    fflush(stdout);
    for (unsigned int i = 0; i < 8; i++) {
        array[i] = i + 1;
        array[i] = array[i] + 1;
    }
    /* Two intervals also exercise cumulative numbering and idempotence. */
    END();
    for (unsigned int interval = 0; interval < 2; interval++) {
        BEGIN();
        BEGIN();
        for (unsigned int i = 0; i < 8; i++) {
            array[8 + i] = i + interval;
            array[8 + i] = array[8 + i] + 3;
        }
        END();
        END();
    }
    for (unsigned int i = 0; i < 8; i++) {
        array[16 + i] = i + 1;
        array[16 + i] = array[16 + i] + 1;
    }
    free((void *)array);
    return 0;
}

/* Exit with a marker interval open. SPDX-License-Identifier: GPL-2.0-or-later */
#include <unistd.h>

int main(void)
{
    __asm__ volatile (
        ".byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x42,0x47" ::: "memory");
    _exit(0);
}

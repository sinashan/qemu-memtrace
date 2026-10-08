/* Experimental diagnostic decoder. SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef I386_PLUGIN_PAGING_H
#define I386_PLUGIN_PAGING_H

#include "qemu/qemu-plugin.h"

/* Pure decoder: production supplies actual RAM reads, unit tests fake reads.
 * All bit constants here are architectural, not host-CPU properties.
 */
typedef enum qemu_plugin_x86_walk_status (*X86PagingRead)(
    void *opaque, uint64_t entry_pa, uint64_t *value);

static inline void x86_plugin_decode_walk(struct qemu_plugin_x86_walk *r,
                                         uint64_t va, X86PagingRead read_entry,
                                         void *opaque)
{
    const uint64_t address_bits = UINT64_C(0x000ffffffffff000);
    struct qemu_plugin_x86_paging *s = &r->paging;
    uint64_t mask, table;

    r->n_entries = 0;
    r->leaf_size = r->pa = 0;
    s->root_pa = 0;
    if (s->phys_bits < 32 || s->phys_bits > 52) {
        r->status = QEMU_PLUGIN_X86_WALK_UNSUPPORTED_PHYS_BITS;
        return;
    }
    mask = ((UINT64_C(1) << s->phys_bits) - 1) & address_bits;
    /* Discard PCID (PCIDE=1) or low cache/control bits (PCIDE=0). */
    s->root_pa = s->cr3 & mask;
    if (s->cr4 & (UINT64_C(1) << 12)) {
        r->status = QEMU_PLUGIN_X86_WALK_UNSUPPORTED_LA57;
        return;
    }
    if (!(s->cr0 & (UINT64_C(1) << 31)) ||
        !(s->cr4 & (UINT64_C(1) << 5)) ||
        !(s->efer & (UINT64_C(1) << 10))) {
        r->status = QEMU_PLUGIN_X86_WALK_UNSUPPORTED_MODE;
        return;
    }
    if ((va >> 47) != 0 && (va >> 47) != UINT64_C(0x1ffff)) {
        r->status = QEMU_PLUGIN_X86_WALK_NONCANONICAL;
        return;
    }
    if (s->cr3 & ~(mask | UINT64_C(0xfff))) {
        r->status = QEMU_PLUGIN_X86_WALK_RESERVED_CR3;
        return;
    }
    table = s->root_pa;
    for (unsigned int level = 4; level > 0; level--) {
        unsigned int shift = 12 + 9 * (level - 1);
        uint64_t entry_pa = table + ((va >> shift) & 0x1ff) * 8;
        uint64_t entry = 0, size;
        bool large;

        r->status = read_entry(opaque, entry_pa, &entry);
        if (r->status != QEMU_PLUGIN_X86_WALK_OK) {
            return;
        }
        r->entries[r->n_entries++] = (struct qemu_plugin_x86_pte) {
            .level = level, .entry_pa = entry_pa, .value = entry,
        };
        /* Nonpresent entries' remaining bits are software-defined. */
        if (!(entry & 1)) {
            r->status = QEMU_PLUGIN_X86_WALK_NONPRESENT;
            return;
        }
        large = (level == 3 || level == 2) && (entry & 0x80);
        if ((entry & (address_bits & ~mask)) ||
            ((entry >> 63) && !(s->efer & (UINT64_C(1) << 11))) ||
            (level == 4 && (entry & 0x80)) ||
            (level == 3 && large && !s->page1g)) {
            r->status = QEMU_PLUGIN_X86_WALK_RESERVED_ENTRY;
            return;
        }
        if (large || level == 1) {
            size = UINT64_C(1) << (large ? shift : 12);
            /* Large-leaf bit 12 is PAT, not a misaligned base bit. */
            if (large && (entry & ((size - 1) & address_bits & ~UINT64_C(0x1000)))) {
                r->status = QEMU_PLUGIN_X86_WALK_RESERVED_ENTRY;
                return;
            }
            r->leaf_size = size;
            r->pa = (entry & mask & ~(size - 1)) | (va & (size - 1));
            r->status = QEMU_PLUGIN_X86_WALK_OK;
            return;
        }
        table = entry & mask;
    }
}

#endif

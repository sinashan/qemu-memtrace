/* Synthetic decoder tests. SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "target/i386/plugin-paging.h"

typedef struct Tables {
    uint64_t va;
    struct qemu_plugin_x86_walk walk;
    struct qemu_plugin_x86_pte entries[4];
    unsigned int reads;
} Tables;

static Tables tables(uint64_t va)
{
    Tables t = {
        .va = va,
        .walk.paging = {
            .cr3 = 0x1000, .cr0 = UINT64_C(1) << 31,
            .cr4 = UINT64_C(1) << 5, .efer = (1 << 10) | (1 << 11),
            .phys_bits = 40, .page1g = true,
        },
    };
    for (unsigned int i = 0; i < 4; i++) {
        unsigned int level = 4 - i;
        t.entries[i] = (struct qemu_plugin_x86_pte) {
            .level = level,
            .entry_pa = (i + 1) * 0x1000 +
                        ((va >> (12 + 9 * (level - 1))) & 0x1ff) * 8,
            .value = i == 3 ? 0x12345007 : (i + 2) * 0x1000 + 7,
        };
    }
    return t;
}

static enum qemu_plugin_x86_walk_status read_entry(void *opaque, uint64_t pa,
                                                  uint64_t *value)
{
    Tables *t = opaque;
    t->reads++;
    for (unsigned int i = 0; i < 4; i++) {
        if (t->entries[i].entry_pa == pa) {
            *value = t->entries[i].value;
            return QEMU_PLUGIN_X86_WALK_OK;
        }
    }
    return QEMU_PLUGIN_X86_WALK_READ_FAILED;
}

static void decode(Tables *t, enum qemu_plugin_x86_walk_status expected)
{
    x86_plugin_decode_walk(&t->walk, t->va, read_entry, t);
    g_assert_cmpint(t->walk.status, ==, expected);
}

static void test_4k(void)
{
    /* Nonzero indices and offsets, low and high canonical halves. */
    uint64_t addresses[] = {UINT64_C(0x123456789abc),
                            UINT64_C(0xffff923456789abc)};
    for (unsigned int j = 0; j < G_N_ELEMENTS(addresses); j++) {
        Tables t = tables(addresses[j]);
        decode(&t, QEMU_PLUGIN_X86_WALK_OK);
        g_assert_cmpuint(t.walk.leaf_size, ==, 4096);
        g_assert_cmpuint(t.walk.pa, ==, 0x12345abc);
        g_assert_cmpuint(t.walk.n_entries, ==, 4);
        for (unsigned int i = 0; i < 4; i++) {
            g_assert_cmpuint(t.walk.entries[i].level, ==, t.entries[i].level);
            g_assert_cmpuint(t.walk.entries[i].entry_pa, ==, t.entries[i].entry_pa);
            g_assert_cmpuint(t.walk.entries[i].value, ==, t.entries[i].value);
        }
    }
}

static void test_large(void)
{
    for (unsigned int level = 2; level <= 3; level++) {
        Tables t = tables(UINT64_C(0x123456789abc));
        uint64_t size = UINT64_C(1) << (12 + 9 * (level - 1));
        uint64_t base = UINT64_C(0x80000000);
        /* Include PAT bit: permitted even though bit 12 is below leaf size. */
        t.entries[4 - level].value = base | 0x1087;
        decode(&t, QEMU_PLUGIN_X86_WALK_OK);
        g_assert_cmpuint(t.walk.n_entries, ==, 5 - level);
        g_assert_cmpuint(t.walk.leaf_size, ==, size);
        g_assert_cmpuint(t.walk.pa, ==, base | (t.va & (size - 1)));
    }
}

static void test_cr3(void)
{
    for (unsigned int pcid = 0; pcid <= 1; pcid++) {
        Tables t = tables(0x12345678);
        t.walk.paging.cr3 |= pcid ? 0xa5b : 0x18; /* PCID vs PWT/PCD */
        t.walk.paging.cr4 |= pcid ? UINT64_C(1) << 17 : 0;
        decode(&t, QEMU_PLUGIN_X86_WALK_OK);
        g_assert_cmpuint(t.walk.paging.root_pa, ==, 0x1000);
    }
    Tables t = tables(0);
    t.walk.paging.cr3 |= UINT64_C(1) << 40;
    decode(&t, QEMU_PLUGIN_X86_WALK_RESERVED_CR3);
    g_assert_cmpuint(t.reads, ==, 0);
}

static void test_nonpresent(void)
{
    for (unsigned int i = 0; i < 4; i++) {
        Tables t = tables(0x12345678);
        t.entries[i].value = UINT64_C(0xfffffffffffffff0);
        decode(&t, QEMU_PLUGIN_X86_WALK_NONPRESENT);
        g_assert_cmpuint(t.walk.n_entries, ==, i + 1);
        g_assert_cmpuint(t.walk.entries[i].value, ==, t.entries[i].value);
    }
}

static void test_modes(void)
{
    Tables t = tables(0);
    t.walk.paging.cr4 |= UINT64_C(1) << 12;
    decode(&t, QEMU_PLUGIN_X86_WALK_UNSUPPORTED_LA57);
    g_assert_cmpuint(t.reads, ==, 0);
    for (unsigned int i = 0; i < 3; i++) {
        t = tables(0);
        if (i == 0) {
            t.walk.paging.cr0 = 0;
        } else if (i == 1) {
            t.walk.paging.cr4 = 0;
        } else {
            t.walk.paging.efer = 0;
        }
        decode(&t, QEMU_PLUGIN_X86_WALK_UNSUPPORTED_MODE);
        g_assert_cmpuint(t.reads, ==, 0);
    }
    t = tables(0);
    t.walk.paging.phys_bits = 64;
    decode(&t, QEMU_PLUGIN_X86_WALK_UNSUPPORTED_PHYS_BITS);
}

static void test_noncanonical(void)
{
    uint64_t addresses[] = {UINT64_C(0x0000800000000000),
                            UINT64_C(0xffff000000000000),
                            UINT64_C(0x0001000000000000)};
    for (unsigned int i = 0; i < G_N_ELEMENTS(addresses); i++) {
        Tables t = tables(addresses[i]);
        decode(&t, QEMU_PLUGIN_X86_WALK_NONCANONICAL);
        g_assert_cmpuint(t.reads, ==, 0);
    }
}

static void test_reserved(void)
{
    Tables t = tables(0);
    t.entries[0].value |= 0x80; /* PS forbidden in PML4 */
    decode(&t, QEMU_PLUGIN_X86_WALK_RESERVED_ENTRY);
    for (unsigned int i = 0; i < 4; i++) {
        t = tables(0);
        t.entries[i].value |= UINT64_C(1) << 40;
        decode(&t, QEMU_PLUGIN_X86_WALK_RESERVED_ENTRY);
        t = tables(0);
        t.walk.paging.efer &= ~(UINT64_C(1) << 11);
        t.entries[i].value |= UINT64_C(1) << 63;
        decode(&t, QEMU_PLUGIN_X86_WALK_RESERVED_ENTRY);
    }
    for (unsigned int level = 2; level <= 3; level++) {
        t = tables(0);
        t.entries[4 - level].value = 0x80002087; /* huge leaf misalignment */
        decode(&t, QEMU_PLUGIN_X86_WALK_RESERVED_ENTRY);
    }
    t = tables(0);
    t.walk.paging.page1g = false;
    t.entries[1].value = 0x80000087;
    decode(&t, QEMU_PLUGIN_X86_WALK_RESERVED_ENTRY);
}

static void test_read_failure(void)
{
    Tables t = tables(0);
    t.entries[2].entry_pa = UINT64_MAX;
    decode(&t, QEMU_PLUGIN_X86_WALK_READ_FAILED);
    g_assert_cmpuint(t.walk.n_entries, ==, 2);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/x86-plugin-paging/4k", test_4k);
    g_test_add_func("/x86-plugin-paging/large", test_large);
    g_test_add_func("/x86-plugin-paging/cr3", test_cr3);
    g_test_add_func("/x86-plugin-paging/nonpresent", test_nonpresent);
    g_test_add_func("/x86-plugin-paging/modes", test_modes);
    g_test_add_func("/x86-plugin-paging/noncanonical", test_noncanonical);
    g_test_add_func("/x86-plugin-paging/reserved", test_reserved);
    g_test_add_func("/x86-plugin-paging/read-failure", test_read_failure);
    return g_test_run();
}

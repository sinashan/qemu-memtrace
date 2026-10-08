/* Experimental RAM-only paging capture. SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "cpu.h"
#include "target/i386/cpu-internal.h"
#include "exec/memory.h"
#include "qemu/bswap.h"
#include "qemu/rcu.h"
#include "target/i386/plugin-paging.h"

static enum qemu_plugin_x86_walk_status read_ram_entry(void *opaque,
                                                       uint64_t pa,
                                                       uint64_t *value)
{
    AddressSpace *as = opaque;
    MemoryRegionSection section;
    enum qemu_plugin_x86_walk_status status = QEMU_PLUGIN_X86_WALK_NOT_RAM;
    void *ptr;

    /* Unlike address_space_ldq/read or the debug walker, this lookup does
     * not invoke MMIO or IOMMU operations. Hold RCU plus a region reference
     * through the direct read. Never populate discarded RAM or use a bounce
     * buffer. Reject ROM/device RAM and unusual discard-managed regions.
     */
    RCU_READ_LOCK_GUARD();
    section = memory_region_find(as->root, pa, 8);
    if (!section.mr) {
        return status;
    }
    if (!memory_region_is_ram(section.mr) || section.readonly ||
        section.mr->rom_device || memory_region_is_ram_device(section.mr) ||
        memory_region_has_ram_discard_manager(section.mr)) {
        goto out;
    }
    if (section.offset_within_address_space != pa ||
        int128_get64(section.size) != 8 ||
        memory_region_size(section.mr) < 8 ||
        section.offset_within_region > memory_region_size(section.mr) - 8) {
        status = QEMU_PLUGIN_X86_WALK_READ_FAILED;
        goto out;
    }
    ptr = memory_region_get_ram_ptr(section.mr);
    if (!ptr) {
        status = QEMU_PLUGIN_X86_WALK_READ_FAILED;
        goto out;
    }
    *value = ldq_le_p((uint8_t *)ptr + section.offset_within_region);
    status = QEMU_PLUGIN_X86_WALK_OK;
out:
    memory_region_unref(section.mr);
    return status;
}

void x86_cpu_plugin_paging_walk(CPUState *cs, uint64_t va,
                               struct qemu_plugin_x86_walk *result)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    AddressSpace *as = cpu_addressspace(cs, cpu_get_mem_attrs(env));

    result->paging = (struct qemu_plugin_x86_paging) {
        .cr3 = env->cr[3], .cr0 = env->cr[0], .cr4 = env->cr[4],
        .efer = env->efer, .phys_bits = cpu->phys_bits,
        .page1g = !!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_PDPE1GB),
    };
    /* Extract a root even for unsupported modes when width is meaningful. */
    if (cpu->phys_bits >= 32 && cpu->phys_bits <= 52) {
        result->paging.root_pa = env->cr[3] & PG_ADDRESS_MASK &
                                ((UINT64_C(1) << cpu->phys_bits) - 1);
    }
    if (env->hflags2 & HF2_NPT_MASK) {
        result->status = QEMU_PLUGIN_X86_WALK_UNSUPPORTED_NESTED;
    } else if (x86_get_a20_mask(env) != -1) {
        result->status = QEMU_PLUGIN_X86_WALK_UNSUPPORTED_A20;
    } else {
        x86_plugin_decode_walk(result, va, read_ram_entry, as);
    }
}

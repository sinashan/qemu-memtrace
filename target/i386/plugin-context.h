/* Experimental committed x86 context; SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef X86_PLUGIN_CONTEXT_H
#define X86_PLUGIN_CONTEXT_H
#include "qemu/plugin.h"
static inline void x86_plugin_context(CPUX86State *env,
    enum qemu_plugin_x86_context_kind kind, uint64_t operand)
{
#ifdef CONFIG_PLUGIN
    if (!test_bit(QEMU_PLUGIN_EV_X86_CONTEXT, env_cpu(env)->plugin_mask)) {
        return;
    }
    X86CPU *cpu = env_archcpu(env);
    struct qemu_plugin_x86_paging after = {
        .cr3 = env->cr[3], .cr0 = env->cr[0], .cr4 = env->cr[4],
        .efer = env->efer, .phys_bits = cpu->phys_bits,
        .page1g = !!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_PDPE1GB),
    };
    if (cpu->phys_bits >= 32 && cpu->phys_bits <= 52) {
        after.root_pa = env->cr[3] & PG_ADDRESS_MASK &
                        ((UINT64_C(1) << cpu->phys_bits) - 1);
    }
    qemu_plugin_x86_context(CPU(cpu), kind, operand, &after);
#endif
}
#endif

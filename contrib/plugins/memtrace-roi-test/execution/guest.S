/* Diskless multiboot x86 architectural-hook regression, not a Linux workload.
 * SPDX-License-Identifier: GPL-2.0-or-later */
.section .multiboot,"a"
.align 4
.long 0x1badb002, 0, -0x1badb002
.section .text
.code32
.global _start
_start:
    cli
    mov $stack_end, %esp
    mov $tables, %edi
    xor %eax, %eax
    mov $(tables_end-tables)/4, %ecx
    rep stosl
    mov $pdpt, %eax
    or $3, %eax
    mov %eax, pml4
    mov %eax, pml4_alt
    mov $pd, %eax
    or $3, %eax
    mov %eax, pdpt
    movl $0x83, pd
    movl $0x200083, pd+8
    mov $pt, %eax
    or $3, %eax
    mov %eax, pd+16
    movl $0x600083, pd+24
    movl $0x300003, pt
    .ifdef FAULT_SECOND
    movl $0, pt+8
    .else
    movl $0x500003, pt+8
    .endif
    movl $0xfee00013, pt+16
    movl $0x800003, pt+24
    movl $0x801003, pt+32
    lgdt gdt_ptr
    mov %cr4, %eax
    or $0x620, %eax /* PAE, OSFXSR, OSXMMEXCPT */
    mov %eax, %cr4
    mov $pml4, %eax
    mov %eax, %cr3
    mov $0xc0000080, %ecx
    rdmsr
    or $0x900, %eax /* LME and NXE */
    wrmsr
    mov %cr0, %eax
    and $~4, %eax
    or $0x80010002, %eax
    mov %eax, %cr0
    ljmp $8, $long_mode
.code64
long_mode:
    mov $16, %eax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $stack_end, %esp
    pxor %xmm0, %xmm0
    .byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x42,0x47
    mov $0x400ff8, %rax
    movdqu %xmm0, (%rax)
    movdqu (%rax), %xmm1
    movdqu %xmm0, 0x400000
    /* Contiguous physical pages, subdivision inside one large leaf, and
     * boundary-aligned/noncrossing controls. */
    movdqu %xmm0, 0x403ff8
    movdqu 0x404000, %xmm1
    movdqu 0x403fe0, %xmm1
    movdqu %xmm0, 0x200ff8
    movdqu 0x200ff8, %xmm1
    movw $7, 0x400fff
    movl $7, 0x400ffd
    movq $7, 0x400ff9
    movl $0, 0x4020b0 /* local APIC EOI: final MMIO cache bypass */
    /* Same root, new physical frame, architectural INVLPG before reuse. */
    movq $0x700003, pt(%rip)
    invlpg (%rax)
    movdqu %xmm0, (%rax)
    /* Same-PA permission change (NX), followed by actual invalidation. */
    btsq $63, pt(%rip)
    invlpg (%rax)
    movdqu (%rax), %xmm1
    mov %cr3, %rbx
    mov %rbx, %cr3 /* same-value reload MUST be observed */
    movdqu (%rax), %xmm1
    mov %cr0, %rbx
    xor $0x10000, %ebx
    mov %rbx, %cr0
    mov %cr4, %rbx
    xor $0x80, %ebx
    mov %rbx, %cr4
    mov $0xc0000080, %ecx
    rdmsr
    wrmsr /* committed same-value EFER update */
    .byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x45,0x4e
    /* Unrecorded context changes must be reflected at the next BEGIN. */
    mov $pml4_alt, %ebx
    mov %rbx, %cr3
    mov $0x400ff8, %eax
    .byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x42,0x47
    .byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x45,0x4e
    .byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x42,0x47
    movdqu (%rax), %xmm1
    .byte 0x0f,0x1f,0x84,0x00,0x56,0x57,0x45,0x4e
    mov $0xf4, %edx
    mov $0x10, %eax
    out %eax, %dx
    hlt
.align 8
gdt:
    .quad 0, 0x00af9a000000ffff, 0x00cf92000000ffff
gdt_ptr:
    .word 23
    .long gdt
.section .bss
.align 4096
tables:
pml4: .skip 4096
pml4_alt: .skip 4096
pdpt: .skip 4096
pd: .skip 4096
pt: .skip 4096
tables_end:
.align 16
.skip 4096
stack_end:
.section .note.GNU-stack,"",@progbits

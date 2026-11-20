; AsmVmexitHandler.asm
; vm-exit entry point -- saves xmm0..xmm5 + mxcsr + all gprs, calls c handler, restores

PUBLIC asm_vmexit_handler

EXTERN vmexit_handler:PROC
EXTERN vmx_vmresume:PROC
EXTERN vmx_return_rsp_for_vmxoff:PROC
EXTERN vmx_return_rip_for_vmxoff:PROC
EXTERN vmx_return_rflags_for_vmxoff:PROC

.code _text

; asm_vmexit_handler
;
; HOST_RIP -- CPU jumps here on every VM-exit with RSP = HOST_RSP
; (vmm_stack + VMM_STACK_SIZE - 0x20, 16-byte aligned).
;
; stack layout after all saves (from rsp upward):
;   [rsp + 0x000] rax (GUEST_REGS starts here)
;   ...
;   [rsp + 0x078] r15
;   [rsp + 0x080] xmm0..xmm5 + mxcsr (0x110 bytes)
;   [rsp + 0x190] rflags (pushfq)
;   [rsp + 0x198] padding (push 0)
;   [rsp + 0x1A0] <-- original HOST_RSP (VMM_STACK_TOP - 0x20)
;   [rsp + 0x1A8] per-core host_nmi_pending (VMM_STACK_TOP - 0x18)
;   [rsp + 0x1B0] scratch (VMM_STACK_TOP - 0x10)
;   [rsp + 0x1B8] vcpu pointer (VMM_STACK_TOP - 0x08)

asm_vmexit_handler PROC

    push    0                   ; alignment padding
    pushfq

    ; save volatile XMM registers + MXCSR (0x110 bytes, keeps 16-byte alignment)
    sub     rsp, 0110h

    movaps  xmmword ptr [rsp+000h], xmm0
    movaps  xmmword ptr [rsp+010h], xmm1
    movaps  xmmword ptr [rsp+020h], xmm2
    movaps  xmmword ptr [rsp+030h], xmm3
    movaps  xmmword ptr [rsp+040h], xmm4
    movaps  xmmword ptr [rsp+050h], xmm5
    stmxcsr dword ptr   [rsp+100h]

    push    r15
    push    r14
    push    r13
    push    r12
    push    r11
    push    r10
    push    r9
    push    r8
    push    rdi
    push    rsi
    push    rbp
    push    rbp                 ; placeholder for rsp (read from VMCS)
    push    rbx
    push    rdx
    push    rcx
    push    rax

    mov     rcx, rsp                ; arg1: PGUEST_REGS
    mov     rdx, [rsp + 01B8h]      ; arg2: vcpu pointer (VMM_STACK_TOP - 0x08)

    sub     rsp, 020h               ; shadow space (x64 ABI)
    call    vmexit_handler
    add     rsp, 020h

    ; check return value: TRUE = vmxoff, FALSE = vmresume
    cmp     al, 1
    je      VmxoffPath

    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    pop     rbp                 ; discard rsp placeholder
    pop     rbp
    pop     rsi
    pop     rdi
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    movaps  xmm0, xmmword ptr [rsp+000h]
    movaps  xmm1, xmmword ptr [rsp+010h]
    movaps  xmm2, xmmword ptr [rsp+020h]
    movaps  xmm3, xmmword ptr [rsp+030h]
    movaps  xmm4, xmmword ptr [rsp+040h]
    movaps  xmm5, xmmword ptr [rsp+050h]
    ldmxcsr dword ptr   [rsp+100h]

    add     rsp, 0110h
    popfq
    add     rsp, 08h

    jmp     vmx_vmresume

asm_vmexit_handler ENDP

; VmxoffPath -- hypervisor shutting down on this core.
; Fetches guest RSP/RIP/RFLAGS BEFORE popping GPRs, then restores XMM0..5,
; MXCSR, all 16 GPRs (RAX = STATUS_SUCCESS from regs->rax), guest RFLAGS,
; guest RSP, and resumes at guest RIP with zero register clobber.

VmxoffPath PROC

    ; fetch guest_rsp, guest_rip, guest_rflags while stack/ABI is clean
    mov     rcx, [rsp + 01B8h]      ; vcpu
    sub     rsp, 020h
    call    vmx_return_rsp_for_vmxoff
    add     rsp, 020h
    mov     [rsp + 01A0h], rax      ; [HOST_RSP + 0x00] = guest_rsp

    mov     rcx, [rsp + 01B8h]      ; vcpu
    sub     rsp, 020h
    call    vmx_return_rip_for_vmxoff
    add     rsp, 020h
    mov     [rsp + 01A8h], rax      ; [HOST_RSP + 0x08] = guest_rip

    mov     rcx, [rsp + 01B8h]      ; vcpu
    sub     rsp, 020h
    call    vmx_return_rflags_for_vmxoff
    add     rsp, 020h
    mov     [rsp + 01B0h], rax      ; [HOST_RSP + 0x10] = guest_rflags

    ; restore all 16 GPRs (regs->rax holds STATUS_SUCCESS)
    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    pop     rbp                     ; discard rsp placeholder
    pop     rbp
    pop     rsi
    pop     rdi
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    ; restore XMM0..XMM5 and MXCSR
    movaps  xmm0, xmmword ptr [rsp+000h]
    movaps  xmm1, xmmword ptr [rsp+010h]
    movaps  xmm2, xmmword ptr [rsp+020h]
    movaps  xmm3, xmmword ptr [rsp+030h]
    movaps  xmm4, xmmword ptr [rsp+040h]
    movaps  xmm5, xmmword ptr [rsp+050h]
    ldmxcsr dword ptr   [rsp+100h]

    ; advance RSP to original HOST_RSP (IF remains 0 from VM-exit)
    add     rsp, 0120h

    ; stage guest_rip at [guest_rsp - 8] and guest_rflags at [guest_rsp - 16]
    push    rcx
    push    rdx
    mov     rcx, [rsp + 010h]       ; guest_rsp
    mov     rdx, [rsp + 018h]       ; guest_rip
    mov     [rcx - 08h], rdx
    mov     rdx, [rsp + 020h]       ; guest_rflags
    mov     [rcx - 10h], rdx
    lea     rcx, [rcx - 10h]        ; target RSP = guest_rsp - 16
    pop     rdx                     ; restore guest rdx
    mov     [rsp + 08h], rcx        ; [HOST_RSP] = guest_rsp - 16
    pop     rcx                     ; restore guest rcx

    mov     rsp, [rsp + 00h]        ; switch to guest stack (guest_rsp - 16)
    popfq                           ; restore guest RFLAGS (rsp = guest_rsp - 8)
    ret                             ; pop guest_rip -> rsp = guest_rsp

VmxoffPath ENDP

END

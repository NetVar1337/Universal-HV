; AsmSvm.asm
; AMD SVM (AMD-V) assembly routines — AMD APM Vol 2 compliant VMLOAD/VMRUN/VMSAVE loop
;
; launch flow (per logical processor):
;   asm_svm_save_state -> svm_virtualize_cpu(rsp) -> asm_svm_launch_loop(vcpu, stack_top, host_cr3, host_idtr)
;
;   1. CLGI blocks interrupts/NMIs while establishing host context.
;   2. RSP switches to vmm_stack_top - 0x30 (16-byte aligned).
;   3. Optional private host CR3 and host IDTR are loaded.
;   4. SvmLoop executes:
;        VMLOAD (guest VMCB PA)  -- loads guest FS/GS/TR/LDTR/KernelGsBase/LSTAR/...
;        VMRUN  (guest VMCB PA)  -- hardware saves host state to HSAVE and enters guest!
;        ; <--- EVERY #VMEXIT RETURNS RIGHT HERE with GIF=0 and host state restored!
;        VMSAVE (guest VMCB PA)  -- saves guest FS/GS/TR/LDTR/... back to guest VMCB
;        save guest GPRs + XMM0..5 + MXCSR
;        VMLOAD (host VMCB PA)   -- restores host hidden state for C handler
;        call svm_exit_handler(regs, vcpu)
;        if return == TRUE -> SvmOffPath (clean SVM exit & return to guest)
;        restore guest XMM0..5 + MXCSR + GPRs
;        jmp SvmLoop

PUBLIC asm_svm_enable
PUBLIC asm_svm_disable
PUBLIC asm_clgi
PUBLIC asm_stgi
PUBLIC asm_svm_vmsave
PUBLIC asm_svm_vmload
PUBLIC asm_svm_vmcall
PUBLIC asm_svm_save_state
PUBLIC asm_svm_restore_state
PUBLIC asm_svm_launch_loop

EXTERN svm_virtualize_cpu:PROC
EXTERN svm_exit_handler:PROC
EXTERN svm_return_rsp_for_off:PROC
EXTERN svm_return_rip_for_off:PROC
EXTERN svm_return_rflags_for_off:PROC

.code _text

; asm_svm_enable — set EFER.SVME (bit 12)
asm_svm_enable PROC
    mov     rcx, 0C0000080h         ; MSR_EFER
    rdmsr
    bts     eax, 12                 ; EFER.SVME = 1
    wrmsr
    ret
asm_svm_enable ENDP

; asm_svm_disable — clear EFER.SVME (bit 12)
asm_svm_disable PROC
    mov     rcx, 0C0000080h         ; MSR_EFER
    rdmsr
    btr     eax, 12                 ; EFER.SVME = 0
    wrmsr
    ret
asm_svm_disable ENDP

asm_clgi PROC
    clgi
    ret
asm_clgi ENDP

asm_stgi PROC
    stgi
    ret
asm_stgi ENDP

; asm_svm_vmsave(UINT64 vmcb_pa /*rcx*/)
asm_svm_vmsave PROC
    mov     rax, rcx
    vmsave  rax
    ret
asm_svm_vmsave ENDP

; asm_svm_vmload(UINT64 vmcb_pa /*rcx*/)
asm_svm_vmload PROC
    mov     rax, rcx
    vmload  rax
    ret
asm_svm_vmload ENDP

; asm_svm_vmcall(UINT64 num /*rcx*/, p1 /*rdx*/, p2 /*r8*/, p3 /*r9*/)
asm_svm_vmcall PROC
    pushfq
    push    r10
    push    r11
    push    r12

    mov     r10, 48564653h          ; 'HVFS'
    mov     r11, 564d43414c4ch      ; 'VMCALL'
    mov     r12, 4e4f485950455256h  ; 'NOHYPERV'

    vmmcall

    pop     r12
    pop     r11
    pop     r10
    popfq
    ret
asm_svm_vmcall ENDP

; asm_svm_save_state — per-LP entry; saves GPRs+RFLAGS and calls svm_virtualize_cpu(rsp)
asm_svm_save_state PROC
    push    0                       ; 16-byte alignment padding
    pushfq
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 0100h              ; shadow space + scratch

    mov     rcx, rsp                ; guest_stack
    call    svm_virtualize_cpu

    ; only reached if svm_virtualize_cpu failed before VMRUN
    jmp     asm_svm_restore_state
asm_svm_save_state ENDP

; asm_svm_restore_state — guest RIP on initial VMRUN; unwinds the save frame
asm_svm_restore_state PROC
    add     rsp, 0100h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    popfq
    add     rsp, 08h
    ret
asm_svm_restore_state ENDP

; asm_svm_launch_loop(
;     PVOID  vcpu            /* rcx */,
;     UINT64 vmm_stack_top   /* rdx */,
;     UINT64 host_cr3        /* r8  */,
;     UINT64 host_idtr_base  /* r9  */)
;
; Stack top layout set up by svm_virtualize_cpu (H = vmm_stack_top - 0x30):
;   [H + 0x28] = vcpu             (vmm_stack_top - 0x08)
;   [H + 0x20] = guest_vmcb_pa    (vmm_stack_top - 0x10)
;   [H + 0x18] = host_nmi_pending (vmm_stack_top - 0x18)
;   [H + 0x10] = host_vmcb_pa     (vmm_stack_top - 0x20)
;   [H + 0x08] = scratch / guest_rip on SvmOffPath
;   [H + 0x00] = scratch / guest_rsp on SvmOffPath
;
; After saving 0x1A0 bytes in SvmLoop, RSP = H - 0x1A0:
;   [rsp + 0x000..0x07F] GUEST_REGS (16 GPRs)
;   [rsp + 0x080..0x18F] XMM0..XMM5 + MXCSR (0x110 bytes)
;   [rsp + 0x190]        host rflags
;   [rsp + 0x198]        padding
;   [rsp + 0x1A0]        H + 0x00 (scratch / guest_rsp)
;   [rsp + 0x1A8]        H + 0x08 (scratch / guest_rip)
;   [rsp + 0x1B0]        H + 0x10 (host_vmcb_pa / guest_rflags on SvmOffPath)
;   [rsp + 0x1B8]        H + 0x18 (host_nmi_pending)
;   [rsp + 0x1C0]        H + 0x20 (guest_vmcb_pa)
;   [rsp + 0x1C8]        H + 0x28 (vcpu)

asm_svm_launch_loop PROC
    clgi
    cli

    ; switch onto the 32KB-aligned VMM stack (H = vmm_stack_top - 0x30, 16-byte aligned)
    lea     rsp, [rdx - 30h]

    ; load private host CR3 if provided
    test    r8, r8
    jz      SkipHostCr3
    mov     cr3, r8
SkipHostCr3:

    ; load private host IDTR if provided
    test    r9, r9
    jz      SkipHostIdt
    sub     rsp, 10h
    mov     word ptr  [rsp + 0], 0FFFh      ; 256 * 16 - 1
    mov     qword ptr [rsp + 2], r9
    lidt    fword ptr [rsp]
    add     rsp, 10h
SkipHostIdt:

SvmLoop:
    mov     rax, [rsp + 20h]        ; guest_vmcb_pa
    vmload  rax                     ; load guest hidden state (FS/GS/TR/LDTR/LSTAR/...)
    vmrun   rax                     ; saves host state to HSAVE, enters guest!

    ; <--- EVERY #VMEXIT LANDS RIGHT HERE (GIF=0, RAX=guest_vmcb_pa, RSP=H)
    vmsave  rax                     ; save guest hidden state back to guest VMCB

    push    0                       ; alignment padding
    pushfq

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
    push    rbp                     ; placeholder for rsp (read from VMCB)
    push    rbx
    push    rdx
    push    rcx
    push    rax

    ; load host hidden state while executing C handler
    mov     rax, [rsp + 01B0h]      ; host_vmcb_pa
    vmload  rax

    mov     rcx, rsp                ; arg1: PGUEST_REGS
    mov     rdx, [rsp + 01C8h]      ; arg2: vcpu pointer

    sub     rsp, 020h
    call    svm_exit_handler
    add     rsp, 020h

    ; check return value: TRUE = clean SVM exit, FALSE = resume guest
    cmp     al, 1
    je      SvmOffPath

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

    jmp     SvmLoop

SvmOffPath:
    ; svm_exit_handler already restored guest CR3, IDTR, GDTR, VMLOADed guest
    ; hidden state, executed STGI (with IF=0), and cleared EFER.SVME!
    mov     rcx, [rsp + 01C8h]      ; vcpu
    sub     rsp, 020h
    call    svm_return_rsp_for_off
    add     rsp, 020h
    mov     [rsp + 01A0h], rax      ; [H + 0x00] = guest_rsp

    mov     rcx, [rsp + 01C8h]      ; vcpu
    sub     rsp, 020h
    call    svm_return_rip_for_off
    add     rsp, 020h
    mov     [rsp + 01A8h], rax      ; [H + 0x08] = guest_rip

    mov     rcx, [rsp + 01C8h]      ; vcpu
    sub     rsp, 020h
    call    svm_return_rflags_for_off
    add     rsp, 020h
    mov     [rsp + 01B0h], rax      ; [H + 0x10] = guest_rflags

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

    ; restore XMM0..XMM5 + MXCSR
    movaps  xmm0, xmmword ptr [rsp+000h]
    movaps  xmm1, xmmword ptr [rsp+010h]
    movaps  xmm2, xmmword ptr [rsp+020h]
    movaps  xmm3, xmmword ptr [rsp+030h]
    movaps  xmm4, xmmword ptr [rsp+040h]
    movaps  xmm5, xmmword ptr [rsp+050h]
    ldmxcsr dword ptr   [rsp+100h]

    ; advance RSP to H (IF is still 0)
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
    mov     [rsp + 08h], rcx        ; [H] = guest_rsp - 16
    pop     rcx                     ; restore guest rcx

    mov     rsp, [rsp + 00h]        ; switch to guest_rsp - 16
    popfq                           ; restore guest RFLAGS (and IF!)
    ret                             ; jump to guest_rip with rsp = guest_rsp
asm_svm_launch_loop ENDP

END

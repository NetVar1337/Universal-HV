; AsmSvm.asm
; AMD SVM (AMD-V) assembly routines
;
; launch flow (per logical processor, via DPC):
;   asm_svm_save_state -> svm_virtualize_cpu(rsp) -> asm_svm_vmrun(vmcb_pa)
;     VMRUN loads the guest from the VMCB and the host state from the
;     HSAVE area. the "guest" here is the already-running OS, so the
;     VMCB save area is initialised with the current CPU state and
;     save.rip = asm_svm_restore_state, which unwinds the DPC stack.
;
; exit flow:
;   on #VMEXIT the CPU loads host RIP/RSP/RAX from the HSAVE area and jumps
;   to asm_svmexit_handler with RSP = HSAVE.rsp (the per-vCPU VMM stack).
;   all other GPRs still hold guest values; we push them, call the C handler,
;   pop them back and re-enter the guest with VMRUN (RAX = VMCB PA, stored
;   at [HOST_RSP]).

PUBLIC asm_svm_enable
PUBLIC asm_clgi
PUBLIC asm_stgi
PUBLIC asm_svm_vmcall
PUBLIC asm_svm_save_state
PUBLIC asm_svm_restore_state
PUBLIC asm_svm_vmrun
PUBLIC asm_svmexit_handler

EXTERN svm_virtualize_cpu:PROC
EXTERN svm_exit_handler:PROC

.code _text

; asm_svm_enable — set EFER.SVME (bit 12)
asm_svm_enable PROC
    mov     rcx, 0C0000080h         ; MSR_EFER
    rdmsr
    bts     eax, 12                 ; EFER.SVME
    wrmsr
    ret
asm_svm_enable ENDP

asm_clgi PROC
    clgi
    ret
asm_clgi ENDP

asm_stgi PROC
    stgi
    ret
asm_stgi ENDP

; asm_svm_vmcall(UINT64 num /*rcx*/, p1 /*rdx*/, p2 /*r8*/, p3 /*r9*/)
; same signature handshake as the VMX VMCALL path
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

; asm_svm_save_state — DPC entry; saves state and calls svm_virtualize_cpu(rsp)
asm_svm_save_state PROC
    push    0                       ; alignment padding
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

    ; only reached if VMRUN failed
    jmp     asm_svm_restore_state
asm_svm_save_state ENDP

; asm_svm_restore_state — set as guest RIP; after a successful VMRUN the
; CPU "returns" here and unwinds the DPC stack exactly as if
; svm_virtualize_cpu had returned.
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

; asm_svm_vmrun — rcx = VMCB physical address; executes VMRUN
asm_svm_vmrun PROC
    mov     rax, rcx
    vmrun
    xor     rax, rax                ; only reached on VMRUN failure
    ret
asm_svm_vmrun ENDP

; asm_svmexit_handler — HSAVE.rip; #VMEXIT lands here.
;
; stack layout after all saves (from rsp upward), mirroring the VMX handler:
;   [rsp + 0x000] rax (GUEST_REGS starts here)
;   ...
;   [rsp + 0x078] r15
;   [rsp + 0x080] xmm0..xmm5 + mxcsr (0x110 bytes)
;   [rsp + 0x190] rflags
;   [rsp + 0x198] padding
;   [rsp + 0x1A0] <-- original HOST_RSP
;   [rsp + 0x1A0] = vmcb_pa (stored by svm_virtualize_cpu at HOST_RSP+0)
;   [rsp + 0x1A8] = vcpu pointer (stored at HOST_RSP+8)
asm_svmexit_handler PROC
    push    0
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
    push    rbp             ; placeholder for rsp (read from VMCB)
    push    rbx
    push    rdx
    push    rcx
    push    rax

    mov     rcx, rsp                ; arg1: PGUEST_REGS
    mov     rdx, [rsp + 01A8h]      ; arg2: vcpu pointer

    sub     rsp, 020h
    call    svm_exit_handler
    add     rsp, 020h

    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    pop     rbp             ; discard rsp placeholder
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

    mov     rax, [rsp]              ; vmcb_pa (stored at HOST_RSP+0)
    vmrun

    ; unreachable: VMRUN either starts the guest or #GPs into the host IDT
    cli
    hlt
    jmp     $
asm_svmexit_handler ENDP

END

; AsmHostIdt.asm
; private host IDT handlers for VMX-root / SVM host mode

PUBLIC asm_host_nmi_handler
PUBLIC asm_host_df_handler
PUBLIC asm_host_gp_handler
PUBLIC asm_host_pf_handler
PUBLIC asm_host_default_handler

EXTERN g_host_fault_info:QWORD

; offsets in HOST_FAULT_INFO:
;   +0x00 valid      (DWORD)
;   +0x04 vector     (DWORD)
;   +0x08 error_code (QWORD)
;   +0x10 rip        (QWORD)
;   +0x18 cs         (QWORD)
;   +0x20 rflags     (QWORD)
;   +0x28 rsp        (QWORD)
;   +0x30 cr2        (QWORD)

.code _text

; Per-core NMI handler:
; Each vCPU's VMM stack is 32KB (0x8000) aligned. The per-core host_nmi_pending
; DWORD lives at [stack_base + 0x8000 - 0x18] = [stack_base + 0x7FE8].
; Computing (RSP | 0x7FFF) gives stack_base + 0x7FFF; subtracting 0x17 gives
; stack_base + 0x7FE8 with zero globals and zero MSR reads!
asm_host_nmi_handler PROC
    push    rax
    mov     rax, rsp
    or      rax, 7FFFh
    lock or DWORD PTR [rax - 17h], 1
    pop     rax
    iretq
asm_host_nmi_handler ENDP

; Common fault recorder for exceptions WITH an error code on stack:
;   [rsp + 0x00] = vector (pushed by stub)
;   [rsp + 0x08] = error_code (pushed by CPU)
;   [rsp + 0x10] = rip
;   [rsp + 0x18] = cs
;   [rsp + 0x20] = rflags
;   [rsp + 0x28] = rsp
host_fault_record_and_halt PROC
    cli
    lea     rdx, g_host_fault_info

    ; first-fault-wins atomic latch
    xor     eax, eax
    mov     ecx, 1
    lock cmpxchg DWORD PTR [rdx], ecx
    jnz     FaultHaltLoop

    mov     eax, DWORD PTR [rsp + 00h]
    mov     DWORD PTR [rdx + 04h], eax  ; vector
    mov     rax, QWORD PTR [rsp + 08h]
    mov     QWORD PTR [rdx + 08h], rax  ; error_code
    mov     rax, QWORD PTR [rsp + 10h]
    mov     QWORD PTR [rdx + 10h], rax  ; rip
    mov     rax, QWORD PTR [rsp + 18h]
    mov     QWORD PTR [rdx + 18h], rax  ; cs
    mov     rax, QWORD PTR [rsp + 20h]
    mov     QWORD PTR [rdx + 20h], rax  ; rflags
    mov     rax, QWORD PTR [rsp + 28h]
    mov     QWORD PTR [rdx + 28h], rax  ; rsp
    mov     rax, cr2
    mov     QWORD PTR [rdx + 30h], rax  ; cr2

FaultHaltLoop:
    hlt
    jmp     FaultHaltLoop
host_fault_record_and_halt ENDP

; #DF (vector 8, CPU pushed error code 0)
asm_host_df_handler PROC
    push    8
    jmp     host_fault_record_and_halt
asm_host_df_handler ENDP

; #GP (vector 13, CPU pushed error code)
asm_host_gp_handler PROC
    push    13
    jmp     host_fault_record_and_halt
asm_host_gp_handler ENDP

; #PF (vector 14, CPU pushed error code)
asm_host_pf_handler PROC
    push    14
    jmp     host_fault_record_and_halt
asm_host_pf_handler ENDP

; catch-all for unexpected vectors (push synthetic error code 0 + vector 0xFF)
asm_host_default_handler PROC
    push    0
    push    0FFh
    jmp     host_fault_record_and_halt
asm_host_default_handler ENDP

END

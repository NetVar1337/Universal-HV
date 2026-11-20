; AsmHostIdt.asm
; private host IDT handlers for VMX-root mode

PUBLIC asm_host_nmi_handler
PUBLIC asm_host_df_handler
PUBLIC asm_host_gp_handler
PUBLIC asm_host_default_handler

EXTERN g_host_nmi_pending:DWORD

.code _text


; NMI handler — sets the global pending flag; the next VM-exit handler
; observes it and injects the NMI into the guest. a single flag is enough
; because there is exactly one guest OS, and it avoids reading
; IA32_TSC_AUX (group-relative processor number, ambiguous on multi-group
; machines).

asm_host_nmi_handler PROC

    push    rax
    mov     eax, 1
    lock or DWORD PTR g_host_nmi_pending, eax
    pop     rax
    iretq

asm_host_nmi_handler ENDP


; #DF in host mode = unrecoverable, halt

asm_host_df_handler PROC

    cli
    hlt
    jmp     $

asm_host_df_handler ENDP


; #GP in host mode = bug, halt

asm_host_gp_handler PROC

    cli
    hlt
    jmp     $

asm_host_gp_handler ENDP


; catch-all for unexpected vectors, halt

asm_host_default_handler PROC

    cli
    hlt
    jmp     $

asm_host_default_handler ENDP


END



EXTERN wNtAllocateVirtualMemory:DWORD               ; Extern keyword indicates that the symbol is defined in another module. Here it's the syscall number for NtAllocateVirtualMemory.
EXTERN sysAddrNtAllocateVirtualMemory:QWORD         ; The actual address of the NtAllocateVirtualMemory syscall in ntdll.dll.

EXTERN wNtWriteVirtualMemory:DWORD                  ; Syscall number for NtWriteVirtualMemory.
EXTERN sysAddrNtWriteVirtualMemory:QWORD            ; The actual address of the NtWriteVirtualMemory syscall in ntdll.dll.

EXTERN wNtCreateThreadEx:DWORD                      ; Syscall number for NtCreateThreadEx.
EXTERN sysAddrNtCreateThreadEx:QWORD                ; The actual address of the NtCreateThreadEx syscall in ntdll.dll.

EXTERN wNtSuspendThread:DWORD                       ; Syscall number for NtSuspendThread.
EXTERN sysAddrNtSuspendThread:QWORD                 ; The actual address of the NtSuspendThread syscall in ntdll.dll.

EXTERN wNtResumeThread:DWORD                        ; Syscall number for NtResumeThread.
EXTERN sysAddrNtResumeThread:QWORD                  ; The actual address of the NtResumeThread syscall in ntdll.dll.

EXTERN wNtCreateProcess:DWORD                    ; Syscall number for NtSetContextThread.
EXTERN sysAddrNtCreateProcess:QWORD              ; The actual address of the NtSetContextThread syscall in ntdll.dll.

EXTERN wNtOpenProcess:DWORD                    ; Syscall number for NtSetContextThread.
EXTERN sysAddrNtOpenProcess:QWORD              ; The actual address of the NtSetContextThread syscall in ntdll.dll.

EXTERN wNtProtectVirtualMemory:DWORD                    ; Syscall number for NtSetContextThread.
EXTERN sysAddrNtProtectVirtualMemory:QWORD              ; The actual address of the NtSetContextThread syscall in ntdll.dll.

EXTERN wNtQueueApcThread:DWORD                    ; Syscall number for NtSetContextThread.
EXTERN sysAddrNtQueueApcThread:QWORD              ; The actual address of the NtSetContextThread syscall in ntdll.dll.

.CODE  ; Start the code section

; Procedure for the NtAllocateVirtualMemory syscall
NtAllocateVirtualMemory PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10.
    mov eax, wNtAllocateVirtualMemory               ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]  ; Jump to the actual syscall.
NtAllocateVirtualMemory ENDP                        ; End of the procedure.

; Procedure for the NtWriteVirtualMemory syscall
NtWriteVirtualMemory PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10.
    mov eax, wNtWriteVirtualMemory                  ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtQueueApcThread]     ; Jump to the actual syscall.
NtWriteVirtualMemory ENDP

; Procedure for the NtCreateThreadEx syscall
NtCreateThreadEx PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10.
    mov eax, wNtCreateThreadEx                      ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtCreateThreadEx]         ; Jump to the actual syscall.
NtCreateThreadEx ENDP


; Procedure for the NtSuspendThread syscall
NtSuspendThread PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10.
    mov eax, wNtSuspendThread                       ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtSuspendThread]          ; Jump to the actual syscall.
NtSuspendThread ENDP

; Procedure for the NtResumeThread syscall
NtResumeThread PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10.
    mov eax, wNtResumeThread                        ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtResumeThread]           ; Jump to the actual syscall.
NtResumeThread ENDP

; Procedure for the NtSetContextThread syscall

NtCreateProcess PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10.
    mov eax, wNtCreateProcess                    ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtCreateProcess]       ; Jump to the actual syscall.
NtCreateProcess ENDP

NtOpenProcess PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10.
    mov eax, wNtOpenProcess                    ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtOpenProcess]       ; Jump to the actual syscall.
NtOpenProcess ENDP

NtProtectVirtualMemory PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10.
    mov eax, wNtProtectVirtualMemory                    ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtProtectVirtualMemory]       ; Jump to the actual syscall.
NtProtectVirtualMemory ENDP

NtQueueApcThread PROC
    mov r10, rcx                                    ; Move the contents of rcx to r10.
    mov eax, wNtQueueApcThread                    ; Move the syscall number into the eax register.
    jmp QWORD PTR [sysAddrNtQueueApcThread]       ; Jump to the actual syscall.
NtQueueApcThread ENDP

END  

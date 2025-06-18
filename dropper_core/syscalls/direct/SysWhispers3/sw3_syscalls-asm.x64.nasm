section .text
    global Sw3NtQuerySystemInformation, Sw3NtCreateSection, Sw3NtMapViewOfSection, Sw3NtUnmapViewOfSection, Sw3NtClose, Sw3NtCreateThreadEx, Sw3NtWaitForSingleObject, Sw3NtDelayExecution, Sw3NtAllocateVirtualMemory, Sw3NtWriteVirtualMemory, Sw3NtProtectVirtualMemory, Sw3NtFreeVirtualMemory, Sw3NtQueueApcThread, Sw3NtOpenProcess, Sw3NtOpenSection
    extern SW3_GetSyscallNumber

Sw3NtQuerySystemInformation:
    mov qword [rsp+8], rcx          ; Save registers.
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0x5B0E63A5       ; Load function hash into ECX.
    call SW3_GetSyscallNumber  ; Resolve function hash into syscall number.
    add rsp, 0x28
    mov rcx, qword [rsp+8]          ; Restore registers.
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall                    ; Invoke system call.
    ret

Sw3NtCreateSection:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0xFAEE3DBE
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtMapViewOfSection:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0x868EA41B
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtUnmapViewOfSection:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0x94609A9
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtClose:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0x54FD0D
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtCreateThreadEx:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0xC21E0C68
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtWaitForSingleObject:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0x8AA4DB89
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtDelayExecution:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0xA92204F
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtAllocateVirtualMemory:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0xC064D4CA
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtWriteVirtualMemory:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0x198D2B27
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtProtectVirtualMemory:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0xD24BE2F2
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtFreeVirtualMemory:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0x3FAD110B
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtQueueApcThread:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0xA695258A
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtOpenProcess:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0xFC29DDB5
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtOpenSection:
    mov qword [rsp+8], rcx
    mov qword [rsp+16], rdx
    mov qword [rsp+24], r8
    mov qword [rsp+32], r9
    sub rsp, 0x28
    mov ecx, 0x88AC6CB7
    call SW3_GetSyscallNumber
    add rsp, 0x28
    mov rcx, qword [rsp+8]
    mov rdx, qword [rsp+16]
    mov r8, qword [rsp+24]
    mov r9, qword [rsp+32]
    mov r10, rcx
    syscall
    ret

Sw3NtResumeThread:
	mov qword [rsp +8], rcx
	mov qword [rsp+16], rdx
	mov qword [rsp+24], r8
	mov qword [rsp+32], r9
	sub rsp, 0x28
	mov ecx, 0x2483E229
	call SW3_GetSyscallNumber
	add rsp, 0x28
	mov rcx, qword [rsp+8]
	mov rdx, qword [rsp+16]
	mov r8, qword [rsp+24]
	mov r9, qword [rsp+32]
	mov r10, rcx
	syscall
	ret

Sw3NtCreateUserProcess:
	mov qword [rsp +8], rcx
	mov qword [rsp+16], rdx
	mov qword [rsp+24], r8
	mov qword [rsp+32], r9
	sub rsp, 0x28
	mov ecx, 0x871D8886
	call SW3_GetSyscallNumber
	add rsp, 0x28
	mov rcx, qword [rsp+8]
	mov rdx, qword [rsp+16]
	mov r8, qword [rsp+24]
	mov r9, qword [rsp+32]
	mov r10, rcx
	syscall
	ret

Sw3NtReadVirtualMemory:
	mov qword [rsp +8], rcx
	mov qword [rsp+16], rdx
	mov qword [rsp+24], r8
	mov qword [rsp+32], r9
	sub rsp, 0x28
	mov ecx, 0x359D4373
	call SW3_GetSyscallNumber
	add rsp, 0x28
	mov rcx, qword [rsp+8]
	mov rdx, qword [rsp+16]
	mov r8, qword [rsp+24]
	mov r9, qword [rsp+32]
	mov r10, rcx
	syscall
	ret

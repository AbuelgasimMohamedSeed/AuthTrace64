BITS 64
DEFAULT REL

GLOBAL _start

%define SYS_WRITE       1
%define SYS_EXIT        60
%define STDOUT_FILENO   1
%define EXIT_SUCCESS    0
%define EXIT_FAILURE    1

section .rodata
    banner:     db "AuthTrace64 v0.1", 10
    banner_len: equ $ - banner

section .text
_start:
    mov eax, SYS_WRITE
    mov edi, STDOUT_FILENO
    lea rsi, [rel banner]
    mov edx, banner_len
    syscall

    test rax, rax
    js .exit_failure
    cmp rax, banner_len
    jne .exit_failure

    mov eax, SYS_EXIT
    mov edi, EXIT_SUCCESS
    syscall

.exit_failure:
    mov eax, SYS_EXIT
    mov edi, EXIT_FAILURE
    syscall
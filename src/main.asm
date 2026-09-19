BITS 64
DEFAULT REL

GLOBAL _start

%define SYS_WRITE           1
%define SYS_CLOSE           3
%define SYS_EXIT            60
%define SYS_OPENAT          257

%define STDOUT_FILENO       1
%define STDERR_FILENO       2
%define AT_FDCWD            -100
%define O_RDONLY            0
%define EINTR               4

%define EXIT_SUCCESS        0
%define EXIT_WRITE_FAILURE  1
%define EXIT_USAGE          2
%define EXIT_OPEN_FAILURE   3
%define EXIT_CLOSE_FAILURE  4

section .rodata
    banner:              db "AuthTrace64 v0.2", 10
    banner_len:          equ $ - banner

    success_message:     db "Input file opened and closed successfully.", 10
    success_message_len: equ $ - success_message

    usage_message:       db "Usage: authtrace <auth-log-file>", 10
    usage_message_len:   equ $ - usage_message

    open_error_message:  db "authtrace: unable to open input file", 10
    open_error_len:      equ $ - open_error_message

    close_error_message: db "authtrace: unable to close input file", 10
    close_error_len:     equ $ - close_error_message

section .text
_start:
    cmp qword [rsp], 2
    jne .usage_error

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, [rsp + 16]
    mov edx, O_RDONLY
    xor r10d, r10d
    syscall

    test rax, rax
    js .open_error

    mov r12, rax
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall

    test rax, rax
    js .close_error

    mov edi, STDOUT_FILENO
    lea rsi, [rel banner]
    mov edx, banner_len
    call write_all
    test eax, eax
    jne .write_error

    mov edi, STDOUT_FILENO
    lea rsi, [rel success_message]
    mov edx, success_message_len
    call write_all
    test eax, eax
    jne .write_error

    mov edi, EXIT_SUCCESS
    jmp exit_process

.usage_error:
    mov edi, STDERR_FILENO
    lea rsi, [rel usage_message]
    mov edx, usage_message_len
    call write_all
    mov edi, EXIT_USAGE
    jmp exit_process

.open_error:
    mov edi, STDERR_FILENO
    lea rsi, [rel open_error_message]
    mov edx, open_error_len
    call write_all
    mov edi, EXIT_OPEN_FAILURE
    jmp exit_process

.close_error:
    mov edi, STDERR_FILENO
    lea rsi, [rel close_error_message]
    mov edx, close_error_len
    call write_all
    mov edi, EXIT_CLOSE_FAILURE
    jmp exit_process

.write_error:
    mov edi, EXIT_WRITE_FAILURE

exit_process:
    mov eax, SYS_EXIT
    syscall
    ud2

write_all:
    test rdx, rdx
    jz .complete

.write_loop:
    mov eax, SYS_WRITE
    syscall

    cmp rax, -EINTR
    je .write_loop
    test rax, rax
    jle .failed

    add rsi, rax
    sub rdx, rax
    jnz .write_loop

.complete:
    xor eax, eax
    ret

.failed:
    mov eax, -1
    ret

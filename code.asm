
BITS 64

BASE equ $$ - 0x1a00

PC equ BASE + 0x4040
RAM equ BASE + 0x4060
HALT equ BASE + 0x4048
ROM equ BASE + 0x140e0
REGS equ BASE + 0x14060

_t0 equ REGS + 0x0
_t1 equ REGS + 0x8
_r0 equ REGS + 0x10
_r1 equ REGS + 0x18
_r2 equ REGS + 0x20
_r3 equ REGS + 0x28
_r4 equ REGS + 0x30
_r5 equ REGS + 0x38
_r6 equ REGS + 0x40
_r7 equ REGS + 0x48
_r8 equ REGS + 0x50
_r9 equ REGS + 0x58
_r10 equ REGS + 0x60
_r11 equ REGS + 0x68
_r12 equ REGS + 0x70
_r13 equ REGS + 0x78


; enc: [10/mode][reg]

; stack ptr @ RAM[0x3000]
; stack base @ RAM[0x3008]

; 0: push [reg]
; 1: const [val]
; 2: add
; 3: mul
; 4: xor
; 5: eqz
; 6: and
; 7: pop [reg]
; 8: reset_stack

; 0x1a00
_entry:
call _handler
jmp _entry - 197

_handler:

mov rax, [rel PC]
lea rbx, [rel ROM]
mov rbx, [rbx]
add rax, rbx
mov bl, [rax]
movzx rbx, bl
mov cl, [rax+1]

lea r8, [rel RAM]
add r8, 0x3000
mov rdx, [r8]

; int3

shr bl, 4
; bl == mode

cmp bl, 0
jz _push
cmp bl, 1
jz _const
cmp bl, 2
jz _add
cmp bl, 3
jz _mul
cmp bl, 4
jz _xor
cmp bl, 5
jz _eqz
cmp bl, 6
jz _and
cmp bl, 7
jz _pop
cmp bl, 8
jz _reset
jmp _end

_push:
lea rax, [rel REGS]
shl cl, 3
add rax, rcx
mov al, [rax]

lea rbx, [rel RAM]
add rbx, rdx
mov [rbx], al
add rdx, 1
mov [r8], rdx

jmp _end

_const:
lea rbx, [rel RAM]
add rbx, rdx
mov [rbx], cl
add rdx, 1
mov [r8], rdx

jmp _end

_add:
lea rax, [rel RAM - 1] ; a
lea rbx, [rel RAM - 2] ; b
mov al, [rax+rdx]
mov bl, [rbx+rdx]
add al, bl
lea rbx, [rel RAM - 2]
mov [rbx + rdx], al

sub rdx, 1
mov [r8], rdx

jmp _end

_mul:
lea rax, [rel RAM - 1] ; a
lea rbx, [rel RAM - 2] ; b
mov al, [rax+rdx]
mov bl, [rbx+rdx]
mul bl
lea rbx, [rel RAM - 2]
mov [rbx+rdx], al

sub rdx, 1
mov [r8], rdx

jmp _end

_xor:
lea rax, [rel RAM - 1] ; a
lea rbx, [rel RAM - 2] ; b
mov al, [rax+rdx]
mov bl, [rbx+rdx]
xor al, bl
lea rbx, [rel RAM - 2]
mov [rbx + rdx], al

sub rdx, 1
mov [r8], rdx

jmp _end

_eqz:
lea rax, [rel RAM - 1] ; a
mov al, [rax+rdx]
test al, al
setz al
lea rbx, [rel RAM - 1]
mov [rbx+rdx], al

jmp _end

_and:
lea rax, [rel RAM - 1] ; a
lea rbx, [rel RAM - 2] ; b
mov al, [rax+rdx]
mov bl, [rbx+rdx]
and al, bl
lea rbx, [rel RAM - 2]
mov [rbx + rdx], al

sub rdx, 1
mov [r8], rdx

jmp _end

_pop:
lea rax, [rel RAM - 1] ; a
mov al, [rax+rdx]
movzx rax, al

lea rbx, [rel REGS]
shl cl, 3
add rbx, rcx

mov [rbx], rax

sub rdx, 1
mov [r8], rdx

jmp _end

_reset:
mov rax, 0x3008
mov [r8], rax

_end:
mov rax, [rel PC]
add rax, 2
mov [rel PC], rax

ret

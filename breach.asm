
_start:
    li sp, 0x10000

    call main

_hijack_return_from_main:

    li r6, 60   ; SYS_exit
    li r7, 0
    call do_syscall

main:
    call exploit

    ; [read][write] (parent->child)
    ; [read][write] (child->parent)

    ; parent -> child @ 0x2000
    li r6, 22
    mov r7, r1
    addi r7, 0x6060
    call do_syscall

    ; child -> parent @ 0x2008
    li r6, 22
    mov r7, r1
    addi r7, 0x6068
    call do_syscall

    li r6, 57       ; SYS_fork
    call do_syscall

    li t0, 0
    jeq r6, t0, main_child
    jmp main_parent

main_parent:
    ; Close pipes
    li r6, 0x2000
    call close_ptr
    
    li r6, 0x200c
    call close_ptr

    call install_seccomp
    jmp parent_handler

main_child:
    ; Close pipes
    li r6, 0x2004
    call close_ptr
    
    li r6, 0x2008
    call close_ptr

    ; Close stdin/stdout
    li r6, 0
    call close
    li r6, 1
    call close

    jmp child_handler


child_setup:
    
    ; mprotect(base+0x1000, 0x2000, 7)
    li r6, 10
    li r7, 0x1000
    add r7, r1
    li r8, 0x2000
    li r9, 0x7
    call do_syscall

    ; copy code into base+0x1a00
    li t0, 0x2020
    ld t0, t1 ; t1 = rom
    la t0, inner_code
    add t1, t0 ; t1 = &code
    mov r7, t1 ; r7 = &code

    li r6, 0x1a00
    add r6, r1 ; r6 = &(base+0x1a00)

    la t1, inner_code_end
    la t0, inner_code
    sub t1, t0
    li t0, 3
    shr t1, t0
    mov r8, t1

    call memcpy

    ; jumptable for #10 at 0x206c
    ; jumptable at 0x2044, target at 0x1a00
    ; return to 0x193b
    li r7, 0xfffff9bcfffff7c8
    li r6, 0x2068
    add r6, r1
    call writeptr

    ; mprotect(base+0x1000, 0x2000, 5)
    li r6, 10
    li r7, 0x1000
    add r7, r1
    li r8, 0x2000
    li r9, 0x5
    call do_syscall

    ret


child_handler:
    ; tx @ 0x2010
    li t0, 0x200c
    ld t0, t0
    li t1, 0xffffffff
    and t0, t1
    li t1, 0x2010
    st t1, t0

    ; rx @ 0x2018
    li t0, 0x2000
    ld t0, t0
    li t1, 0xffffffff
    and t0, t1
    li t1, 0x2018
    st t1, t0

    ; rom @ 0x2020
    li r6, 0x140e0
    add r6, r1
    call readptr
    li t1, 0x2020
    st t1, r6

    call child_setup

_child_handler_loop:
    ; read(rx, &rom, 8);
    li r6, 0 ; SYS_read
    li t0, 0x2018
    ld t0, r7 ; fd=rx
    li t0, 0x2020
    ld t0, r8 ; rom
    li r9, 8
    call do_syscall

    ; int read_size = rom[0];
    li t0, 0x2020
    ld t0, r6
    call readptr
    mov r9, r6 ; read_size

    ; read(rx, &rom, read_size);
    li r6, 0 ; SYS_read
    li t0, 0x2018
    ld t0, r7 ; fd=rx
    li t0, 0x2020
    ld t0, r8 ; rom
    call do_syscall

_child_hijack_return:

    call child_check_flag

    ; rom[0] = res;
    mov r7, r6
    li t0, 0x2020
    ld t0, r6
    call writeptr

    ; write(tx, &rom, 1);
    li r6, 1 ; SYS_write
    li t0, 0x2010
    ld t0, r7 ; fd=tx
    li t0, 0x2020
    ld t0, r8 ; rom
    li r9, 1
    call do_syscall

    jmp _child_handler_loop

child_check_flag:
    li t0, 0
    ldm t0, r6
    li t0, 0xffffffffff
    and r6, t0
    li t0, 0x7b65636964
    jeq r6, t0, _check
    jmp _check_bad
_check:
    flag_checker b'dice{st4ying_ins1de_vms_1s_0verr4ted}'
    jmp _check_done
_check_bad:
    li r6, 0
_check_done:
    ret


parent_handler:
    ; while (1) {
    ;     puts("Flag: ");

    ;     if (read(0, &rom, 0x40) == 1) {
    ;         return;
    ;     }
    ;     send(tx, &rom, 0x40);

    ;     puts("Checking...");

    ;     read(rx, &rom, 0x1);
    ;     int val = *rom;

    ;     if (val) {
    ;         puts("Correct!");
    ;         return;
    ;     } else {
    ;         puts("Wrong!");
    ;     }
    ; }

    ; tx @ 0x2010
    li t0, 0x2004
    ld t0, t0
    li t1, 0xffffffff
    and t0, t1
    li t1, 0x2010
    st t1, t0

    ; rx @ 0x2018
    li t0, 0x2008
    ld t0, t0
    li t1, 0xffffffff
    and t0, t1
    li t1, 0x2018
    st t1, t0

    ; rom @ 0x2020
    li r6, 0x140e0
    add r6, r1
    call readptr
    li t1, 0x2020
    st t1, r6

_parent_handler_loop:

    ; puts("Flag: \n");
    la r6, str_flag
    la r7, str_flag_end
    call puts

    ; read(0, &rom, 0x40);
    li r6, 0 ; SYS_read
    li r7, 0 ; fd=1
    li t0, 0x2020
    ld t0, r8 ; rom
    li r9, 0x60
    call do_syscall

    li t0, 1
    jeq r6, t0, _parent_handler_leave

    ; *0x2028 = read_size
    li t1, 0x2028
    st t1, r6

    ; write(tx, &read_size, 8);
    li r6, 1 ; SYS_write
    li t0, 0x2010
    ld t0, r7
    mov r8, r1
    addi r8, 0x6088
    li r9, 0x8
    call do_syscall

    ; write(tx, &rom, read_size);
    li r6, 1 ; SYS_write
    li t0, 0x2010
    ld t0, r7
    li t0, 0x2020
    ld t0, r8 ; rom
    li t1, 0x2028
    ld t1, r9
    call do_syscall

    ; puts("Checking...\n");
    la r6, str_checking
    la r7, str_checking_end
    call puts

    ; read(rx, &rom, 1);
    li r6, 0 ; SYS_read
    li t0, 0x2018
    ld t0, r7
    li t0, 0x2020
    ld t0, r8 ; rom
    li r9, 1
    call do_syscall

    ; int val = rom[0];
    li t0, 0x2020
    ld t0, r6 ; rom
    call readptr
    li t0, 0xff
    and r6, t0

    li t0, 1
    jeq r6, t0, _parent_correct

_parent_wrong:
    ; puts("Wrong!\n");
    la r6, str_wrong
    la r7, str_wrong_end
    call puts
    jmp _parent_handler_loop

_parent_correct:
    ; puts("Correct!\n");
    la r6, str_correct
    la r7, str_correct_end
    call puts

_parent_handler_leave:
    ret


; r6 : ptr to socket fd
close_ptr:
    mov t0, r6
    ld t0, t0
    li t1, 0xffffffff
    and t0, t1
    li r6, 3
    mov r7, t0
    call do_syscall
    ret


; r6 : fd number
close:
    mov r7, r6
    li r6, 3
    call do_syscall
    ret


; r6 : raw pointer to dest
; r7 : raw src pointer
; r8 ; number of qwords
memcpy:
    li r9, 0

_memcpy_loop:
    push r9
    push r8

    push r6
    push r7

    mov r6, r7
    call readptr
    mov r8, r6 ; r8 = *dst

    pop r7
    pop r6
    push r6
    push r7

    mov r7, r8
    call writeptr ; *src = r8

    pop r7
    pop r6

    addi r6, 8
    addi r7, 8

    pop r8
    pop r9
    
    addi r9, 1
    jeq r9, r8, _memcpy_end
    jmp _memcpy_loop

_memcpy_end:
    ret


install_seccomp:
    li r6, 0x9d
    li r7, 38
    li r8, 1
    li r9, 0
    li r10, 0
    li r11, 0
    call do_syscall

    ; 0x1000 : len // 8
    ; 0x1008 : &seccomp

    ; Write length
    la t0, seccomp_rules
    la t1, seccomp_rules_end
    sub t1, t0
    li t0, 3
    shr t1, t0
    li t0, 0x1000
    st t0, t1

    ; Write ptr
    mov r6, r1
    li t0, 0x140e0
    add r6, t0
    call readptr
    la t0, seccomp_rules
    add r6, t0
    li t0, 0x1008
    st t0, r6

    li r6, 0x9d
    li r7, 22
    li r8, 2
    mov r9, r1
    li t0, 0x5060
    add r9, t0
    call do_syscall

    ret


; r6 -> rax
; r7 -> rdi
; r8 -> rsi
; r9 -> rdx
; r10 -> r10
; r11 -> r8
do_syscall:
    li t0, 0x8008 ; r10
    st t0, r10
    li t0, 0x8018 ; r8
    st t0, r11
    li t0, 0x8050 ; rax
    st t0, r6
    li t0, 0x8060 ; rdi
    st t0, r7
    li t0, 0x8070 ; rsi
    st t0, r8
    li t0, 0x8080 ; rdx
    st t0, r9

    la r2, _rop_syscall
    call exec
    ret


; r6 -> ptr
readptr:
    li t0, 0x8008
    st t0, r6
    li t0, 0x8018
    st t0, r6

    la r2, _rop_readptr
    call exec
    ret


; r6 -> ptr
; r7 -> val
writeptr:
    li t0, 0x8008
    st t0, r7
    li t0, 0x8020
    st t0, r6

    la r2, _rop_writeptr
    call exec
    ret


; r6 -> rom offset
; r7 -> end
puts:
    sub r7, r6
    push r7
    push r6

    li r6, 0x140e0
    add r6, r1
    call readptr

    pop r8
    add r8, r6

    pop r9

    li r6, 1 ; SYS_write
    li r7, 1 ; stdout
    call do_syscall

    ret


; r0 : libc base
; r1 : binary base
; r2 : pointer to ropchain (ROM)
exec:
    ; Write original ropchain.
    mov r3, r2
    li r2, 0x8000
    call write_ropchain

    ; Write loopback tail.
    la r3, _rop_loopback
    call write_ropchain

    ; Overwrite hooked rsp.
    call overwrite_hooked

    ; Trigger.
    hlt

_hook_after_exec_chain:

    ret


exploit:
    li r0, 48
    li r1, 0
    sub r1, r0
    ld r1, r0

    li t0, 0x1eb980
    sub r0, t0

    ; r0 = libc base

    li t0, 0x1ef2e0
    mov r1, r0
    add r1, t0

    ; r1 = __environ
    ; putv r1

    li t0, 0x1150
    li t1, 0
    sub t1, t0
    ldm t1, r2
    li t0, 0x1100
    add r2, t0

    ; r2 = addr of rom
    ; putv r2

    mov t0, r1
    sub t0, r2
    ldm t0, r3

    ; r3 = stack leak
    ; putv r3

    li t0, 0xe8
    mov r4, r3
    sub r4, t0
    ; r4 = ptr to main
    mov t0, r4
    sub t0, r2
    ldm t0, r4
    li t0, 0x1229
    sub r4, t0

    ; r4 = binary base
    ; putv r4

    mov r5, r3
    subi r5, 0x108
    ; ptr to ret

    mov r1, r4
    mov r2, r5
    call overwrite_original

    ; r0 = libc base
    ; r1 = binary base
    li r2, 0x8000
    la r3, _rop_loopback
    call write_ropchain
    
    hlt

    ; Now we are executing with the right stack context.
    ret


; r0 : libc base
; r1 : binary base
; r2 : write offset in RAM
; r3 : rop start (ROM)
; ----
; returns next ram ptr in r2
write_ropchain:
    push r4
    push r5
_write_ropchain_loop:
    ldm r3, t0
    li t1, 0x676e614765636944
    xor t0, t1

    li t1, 0xdeadbeefdeadbeef
    jeq t0, t1, _write_ropchain_end

    mov r4, t0
    mov r5, t0

    li t0, 0xffffffffffffff
    and r4, t0

    li t0, 56
    shr r5, t0

    li t0, 0
    jeq r5, t0, _write_ropchain_raw
    li t0, 0x34
    jeq r5, t0, _write_ropchain_gadget
    li t0, 0x56
    jeq r5, t0, _write_ropchain_binary
    jmp _write_ropchain_cont

_write_ropchain_raw:
    st r2, r4
    jmp _write_ropchain_cont

_write_ropchain_gadget:
    mov t0, r0
    add t0, r4
    st r2, t0
    jmp _write_ropchain_cont

_write_ropchain_binary:
    mov t0, r1
    add t0, r4
    st r2, t0
    jmp _write_ropchain_cont


_write_ropchain_cont:
    addi r3, 8
    addi r2, 8
    jmp _write_ropchain_loop

_write_ropchain_end:
    pop r5
    pop r4
    ret


; r0 : libc base
; r1 : binary base
; r2 : ptr to ret
overwrite_original:
    ; pop rsp
    ; <jumpback>
    mov r7, r2
    sub r7, r1
    subi r7, 0x4060

    stoff r7, r0, pop_rsp
    addi r7, 8
    mov r8, r1
    addi r8, 0xc060
    st r7, r8

    ret


; after rop pivot, rsp is at RAM+0x7fa8
; r0 : libc base
; r1 : binary base
overwrite_hooked:
    ; pop rsp
    ; <jumpback>
    li r8, 0x7fa8

    stoff r8, r0, pop_rsp
    addi r8, 8
    mov r9, r1
    addi r9, 0xc060
    st r8, r9

    ret


_rop_loopback:
    .g pop_rax
    .b 0x193b   ; main_loop
    .g pop_rdi
    .b 0x4048   ; halt
    .g pop_rcx
    .v 0
    .g mov_rdi_rcx
    .g pop_rdi
    .b 0xc060
    .g pop_rcx
    .g call_rax     ; as a value
    .g mov_rdi_rcx
    .g pop_rbp
    .b 0xc000
    .g pop_rsp
    .b 0xc060
    .end


_rop_syscall:
    .g pop_rdx_rcx_rbx
    .empty          ; r10 = 0x8008
    .empty
    .empty          ; r8 = 0x8018
    .g pop_rax
    .g ret
    .g mov_r10_rdx.jmp_rax
    .g mov_r8_rbx.mov_rax_r8.pop_rbx
    .empty

    .g pop_rax
    .empty        ; rax=0x8050
    .g pop_rdi
    .empty        ; rdi=0x8060
    .g pop_rsi
    .empty        ; rsi=0x8070
    .g pop_rdx_rcx_rbx
    .empty        ; rdx=0x8080
    .empty        
    .empty        

    .g syscall
    .g pop_rbx
    .b 0x140a0    ; &r6
    .g mov_rbx_rax_p3
    .v 0
    .v 0
    .v 0
    .end


_rop_readptr:
    .g pop_rsi
    .empty      ; ptr=0x8008
    .g pop_rdi
    .empty      ; ptr=0x8018
    .g mov_rdx_rsi.mov_rdi_rdx
    .g pop_rdi
    .b 0x140a0    ; &r6
    .g mov_rdi_rdx
    .end


_rop_writeptr:
    .g pop_rdx_rbx
    .empty      ; ptr=0x8008
    .empty
    .g pop_rdi
    .empty      ; ptr=0x8020
    .g mov_rdi_rdx
    .end


seccomp_rules:
    .s b' \x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\a>\x00\x00\xC0 \x00\x00\x00\x00\x00\x00\x005\x00\x05\x00\x00\x00\x00@\x15\x00\x03\x00\x01\x00\x00\x00\x15\x00\x02\x00\x00\x00\x00\x00\x15\x00\x01\x00<\x00\x00\x00\x06\x00\x00\x00\x05\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x00\x00'
seccomp_rules_end:

inner_code:
    .include code
    .s b'\x90\x90\x90\x90\x90\x90\x90\x90'
inner_code_end:

str_flag:
    .s b'Flag: '
str_flag_end:

str_checking:
    .s b'Checking...\n'
str_checking_end:

str_wrong:
    .s b'Wrong!\n'
str_wrong_end:

str_correct:
    .s b'Correct!\n'
str_correct_end:

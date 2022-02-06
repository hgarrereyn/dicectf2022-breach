
import argparse
import struct
import random

from z3 import *


rmap = {
    't0': 0,
    't1': 1,
    'r0': 2,
    'r1': 3,
    'r2': 4,
    'r3': 5,
    'r4': 6,
    'r5': 7,
    'r6': 8,
    'r7': 9,
    'r8': 10,
    'r9': 11,
    'r10': 12,
    'r11': 13,
    'r12': 14,
    'sp': 15,
}

# ; 0x270b1 : call rax
# ; 0x4a550 : pop rax ; ret
# ; 0x66229 : syscall ; ret
# ; 0xba056 : mov qword ptr [rdi], rcx ; ret
# ; 0xba040 : mov rdx, qword ptr [rsi] ; mov qword ptr [rdi], rdx ; ret

# ; 0x26b72 pop rdi ; ret
# ; 0x27529 pop rsi ; ret
# ; 0x1056fd pop rdx ; pop rcx ; pop rbx ; ret
# ; 0x4a550 pop rax ; ret
# ; 0x0000000000032b5a : pop rsp ; ret
# ; 0x000000000009f822 : pop rcx ; ret
# 0x00000000000256c0 : pop rbp ; ret
gadgets = {
    'call_rax': 0x270b1,
    'pop_rax': 0x4a550,
    'syscall': 0x66229,
    'mov_rdi_rcx': 0xba056,
    'pop_rdi': 0x26b72,
    'pop_rcx': 0x9f822,
    'pop_rsp': 0x32b5a,
    'pop_rbp': 0x256c0,
    'pop_rdx_rcx_rbx': 0x1056fd,
    'pop_rsi': 0x27529,
    'mov_rbx_rax_p3': 0x162d94,
    'pop_rbx': 0x331ff,
    'mov_rdx_rsi.mov_rdi_rdx': 0xba040,
    'mov_rdi_rdx': 0x4514d,
    'mov_r8_rbx.mov_rax_r8.pop_rbx': 0x11fdaa,
    'mov_r10_rdx.jmp_rax': 0x7b0cb,
    'ret': 0x25679,
    'pop_rdx_rbx': 0x162866,
}


class Label(object):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f'Label({self.name})'


class Instr(object):
    call_idx = 0

    def __init__(self, code):
        self.code = code

    def __repr__(self):
        return f'Instr({self.code})'

    def expand(self):
        parts = self.code.replace(',','').split()

        if parts[0] == 'pushi':
            return [
                Instr(f'li t0, 8'),
                Instr(f'sub sp, t0'),
                Instr(f'li t0, {parts[1]}'),
                Instr(f'st sp, t0'),
            ]
        elif parts[0] == 'push':
            return [
                Instr(f'li t0, 8'),
                Instr(f'sub sp, t0'),
                Instr(f'st sp, {parts[1]}'),
            ]
        elif parts[0] == 'pop':
            return [
                Instr(f'ld sp, {parts[1]}'),
                Instr(f'li t0, 8'),
                Instr(f'add sp, t0'),
            ]
        elif parts[0] == 'call':
            lbl = f'_ret_{Instr.call_idx}'
            Instr.call_idx += 1
            return [
                Instr(f'li t0, 8'),
                Instr(f'sub sp, t0'),
                Instr(f'la t0, {lbl}'),
                Instr(f'st sp, t0'),
                Instr(f'jmp {parts[1]}'),
                Label(lbl),
            ]
        elif parts[0] == 'ret':
            return [
                Instr(f'ld sp, t1'),
                Instr(f'li t0, 8'),
                Instr(f'add sp, t0'),
                Instr(f'jr t1'),
            ]
        elif parts[0] == 'addi':
            return [
                Instr(f'li t0, {parts[2]}'),
                Instr(f'add {parts[1]}, t0'),
            ]
        elif parts[0] == 'subi':
            return [
                Instr(f'li t0, {parts[2]}'),
                Instr(f'sub {parts[1]}, t0'),
            ]
        elif parts[0] == 'stoff':
            # stoff addr, base, gadget
            assert parts[3] in gadgets, f'Gadget "{parts[3]}" not found'
            return [
                Instr(f'mov t0, {parts[2]}'),
                Instr(f'li t1, {gadgets[parts[3]]}'),
                Instr(f'add t0, t1'),
                Instr(f'st {parts[1]}, t0'),
            ]
        elif parts[0] == 'flag_checker':
            return gen_flag_checker(eval(parts[1]))
        else:
            return [self]

    def assemble(self, warn=False, label_map={}) -> bytes:
        parts = self.code.replace(',','').split()
        op = parts[0]

        aluops = ['add', 'sub', 'mul', 'mod', 'and', 'or', 'xor', 'shr']

        if op == 'hlt':
            return struct.pack('<B', 0)
        elif op == 'li':
            rval = rmap[parts[1]]
            val = eval(parts[2])
            return struct.pack('<B', 1 | (rval << 4)) + struct.pack('<Q', val)
        elif op == 'la':
            rval = rmap[parts[1]]
            lbl = parts[2]
            target = 0
            if lbl in label_map:
                target = label_map[lbl]
            elif warn:
                print(f'[!] Missing label "{lbl}"')
            return struct.pack('<B', 1 | (rval << 4)) + struct.pack('<Q', target)
        elif op == 'mov':
            dst = rmap[parts[1]]
            src = rmap[parts[2]]
            return struct.pack('<B', 2) + struct.pack('<B', dst + (src << 4))
        elif op in aluops:
            aluop = aluops.index(op)
            dst = rmap[parts[1]]
            src = rmap[parts[2]]
            return struct.pack('<B', 3 + (aluop << 4)) + struct.pack('<B', dst + (src << 4))
        elif op == 'st':
            addr = rmap[parts[1]]
            val = rmap[parts[2]]
            return struct.pack('<B', 4) + struct.pack('<B', addr + (val << 4))
        elif op == 'ld':
            addr = rmap[parts[1]]
            val = rmap[parts[2]]
            return struct.pack('<B', 5) + struct.pack('<B', addr + (val << 4))
        elif op == 'ldm':
            addr = rmap[parts[1]]
            val = rmap[parts[2]]
            return struct.pack('<B', 6) + struct.pack('<B', addr + (val << 4))
        elif op == 'jmp':
            lbl = parts[1]
            target = 0
            if lbl in label_map:
                target = label_map[lbl]
            elif warn:
                print(f'[!] Missing label "{lbl}"')
            return struct.pack('<B', 7) + struct.pack('<Q', target)
        elif op == 'jr':
            target = rmap[parts[1]]
            return struct.pack('<B', 8 + (target << 4))
        elif op == 'jeq':
            v1 = rmap[parts[1]]
            v2 = rmap[parts[2]]
            lbl = parts[3]
            target = 0
            if lbl in label_map:
                target = label_map[lbl]
            elif warn:
                print(f'[!] Missing label "{lbl}"')
            return struct.pack('<B', 9) + struct.pack('<B', v1 | (v2 << 4)) + struct.pack('<Q', target)
        elif op == 'putv':
            val = rmap[parts[1]]
            return struct.pack('<B', 10) + struct.pack('<B', val)
        elif op == '.s':
            # string type
            return eval(self.code.split('.s ')[1])
        elif op == '.g':
            # libc gadget
            assert parts[1] in gadgets, f'Gadget "{parts[1]}" not found'
            return struct.pack('<Q', (gadgets[parts[1]] | (0x34 << 56)) ^ 0x676e614765636944)
        elif op == '.b':
            # binary offset
            return struct.pack('<Q', (eval(parts[1]) | (0x56 << 56)) ^ 0x676e614765636944)
        elif op == '.empty':
            # binary offset
            return struct.pack('<Q', (0x99 << 56) ^ 0x676e614765636944)
        elif op == '.v':
            # raw value
            return struct.pack('<Q', eval(parts[1]) ^ 0x676e614765636944)
        elif op == '.end':
            return struct.pack('<Q', 0xdeadbeefdeadbeef ^ 0x676e614765636944)
        elif op == '.include':
            return open(parts[1], 'rb').read()

        # psudo-ops after child overwrites putv
        elif op == 'vpush':
            return struct.pack('<B', 10 + (0 << 4)) + struct.pack('<B', rmap[parts[1]])
        elif op == 'vconst':
            return struct.pack('<B', 10 + (1 << 4)) + struct.pack('<B', eval(parts[1]))
        elif op == 'vadd':
            return struct.pack('<B', 10 + (2 << 4)) + struct.pack('<B', 0)
        elif op == 'vmul':
            return struct.pack('<B', 10 + (3 << 4)) + struct.pack('<B', 0)
        elif op == 'vxor':
            return struct.pack('<B', 10 + (4 << 4)) + struct.pack('<B', 0)
        elif op == 'veqz':
            return struct.pack('<B', 10 + (5 << 4)) + struct.pack('<B', 0)
        elif op == 'vand':
            return struct.pack('<B', 10 + (6 << 4)) + struct.pack('<B', 0)
        elif op == 'vpop':
            return struct.pack('<B', 10 + (7 << 4)) + struct.pack('<B', rmap[parts[1]])
        elif op == 'vreset':
            return struct.pack('<B', 10 + (8 << 4)) + struct.pack('<B', 0)

        else:
            print(f'[!] Unknown op: "{op}"')

        return b''


def gen_flag_checker(flag):
    random.seed(42)

    ops = []
    ops.append(Instr('vreset'))

    cstr = []
    bflag = [BitVec('f%d' % i, 8) for i in range(len(flag))]

    num_constraints = 0

    FN = [
        lambda a,b: (a + b) & 0xff,
        lambda a,b: (a * b) & 0xff,
        lambda a,b: (a ^ b),
    ]

    FNN = ['vadd', 'vmul', 'vxor']

    while True:
        a = random.randint(0, len(flag)-1)
        b = random.randint(0, len(flag)-1)
        c = random.randint(0, len(flag)-1)
        d = random.randint(0, len(flag)-1)

        # [add, mul, xor]
        o0 = random.randint(0, 2)
        o1 = random.randint(0, 2)
        o2 = random.randint(0, 2)
        o3 = random.randint(0, 2)
        o4 = random.randint(0, 2)
        o5 = random.randint(0, 2)

        r0 = random.randint(0, 255)
        r1 = random.randint(0, 255)
        r2 = random.randint(0, 255)

        # (((a o0 b) o1 r0) o2 ((c o3 d) o4 r1)) o5 r2

        print(o0, o1, o2, o3, o4, o5)

        target = (lambda flag: FN[o5]( FN[o2]( FN[o1]( FN[o0](flag[a], flag[b]), r0 ), FN[o4]( FN[o3](flag[c], flag[d]), r1 ) ), r2 ))

        lit = target(flag)
        zval = target(bflag)

        cstr.append(zval == lit)

        ops += [
            Instr(f'li t0, {a}'),
            Instr(f'ldm t0, r6'),
            Instr(f'li t0, {b}'),
            Instr(f'ldm t0, r7'),
            Instr(f'li t0, {c}'),
            Instr(f'ldm t0, r8'),
            Instr(f'li t0, {d}'),
            Instr(f'ldm t0, r9'),

            Instr(f'vpush r6'),
            Instr(f'vpush r7'),
            Instr(FNN[o0]),
            Instr(f'vconst {r0}'),
            Instr(FNN[o1]),

            Instr(f'vpush r8'),
            Instr(f'vpush r9'),
            Instr(FNN[o3]),
            Instr(f'vconst {r1}'),
            Instr(FNN[o4]),

            Instr(FNN[o2]),
            Instr(f'vconst {r2}'),
            Instr(FNN[o5]),

            Instr(f'vconst {lit}'),
            Instr(f'vxor'),
            Instr(f'veqz'),
        ]

        num_constraints += 1

        # Check solutions
        s = Solver()
        for c in cstr:
            s.add(c)

        assert s.check() == sat
        m = s.model()

        if any(m[bflag[i]] is None for i in range(len(flag))):
            continue

        sol = bytes([m[bflag[i]].as_long() for i in range(len(flag))])
        print(num_constraints, sol)
        s.add(Not(And([
            bflag[i] == sol[i] for i in range(len(flag))
        ])))

        if s.check() != sat:
            print('One solution!')
            break


    ops += [Instr('vand')] * (num_constraints - 1)
    ops += [
        Instr('vpop r6')
    ]

    return ops


def proprocess(asm):
    lines = asm.split('\n')
    lines = [x.split(';')[0] for x in lines]
    lines = [x.strip() for x in lines]
    lines = [x for x in lines if x != '']
    return lines


def main(args):
    asm = open(args.program, 'r').read()
    lines = proprocess(asm)

    code = []
    for line in lines:
        if line.endswith(':'):
            code.append(Label(line[:-1]))
        else:
            code.append(Instr(line))

    exp_code = []
    for c in code:
        if type(c) is Label:
            exp_code.append(c)
        else:
            # Expand macros.
            exp_code += c.expand()
    code = exp_code

    for c in code:
        print(c)

    label_map = {}

    # First pass, no labels.
    text = b''
    for c in code:
        if type(c) is Instr:
            text += c.assemble()
        else:
            label_map[c.name] = len(text)

    # Second pass, with labels.
    text = b''
    for c in code:
        if type(c) is Instr:
            text += c.assemble(warn=True, label_map=label_map)

    print(label_map)

    open(args.output, 'wb').write(text)


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('program')
    parser.add_argument('output')
    args = parser.parse_args()
    main(args)

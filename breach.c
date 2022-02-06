
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>


// #define DEBUG 1

#ifdef DEBUG
    #define TRACE(...) printf(__VA_ARGS__)
#else
    #define TRACE(...) 0
#endif


uint64_t pc = 0;
uint64_t regs[16];

uint8_t halt = 0;

uint8_t *rom;
uint8_t ram[0x10000];

int main(int argc, char **argv) {

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    if (argc != 2) {
        printf("Usage: %s program.bin\n", argv[0]);
        exit(0);
    }

    FILE *fd = fopen(argv[1], "rb");
    fseek(fd, 0, SEEK_END);
    size_t size = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    rom = malloc(size);
    fread(rom, 1, size, fd);

    while (!halt) {
        uint8_t op = rom[pc] & 15;

        TRACE("[0x%04lx] (%d) :: ", pc, op);

        switch (op) {
            // HLT
            case 0: {
                halt = 1;
                pc += 1;
                TRACE("hlt\n");
                break;
            }

            // LI
            case 1: {
                uint8_t dst = (rom[pc] >> 4) & 15;
                uint64_t val = *(uint64_t *)(&rom[pc+1]);
                regs[dst] = val;
                pc += 9;
                TRACE("li r%d, 0x%lx\n", dst, val);
                break;
            }

            // MOV
            case 2: {
                uint8_t dst = rom[pc+1] & 15;
                uint8_t src = (rom[pc+1] >> 4) & 15;
                regs[dst] = regs[src];
                pc += 2;
                TRACE("mov r%d, r%d\n", dst, src);
                break;
            }

            // ALU
            case 3: {
                uint8_t aluop = (rom[pc] >> 4) & 15;
                uint8_t dst = rom[pc+1] & 15;
                uint8_t src = (rom[pc+1] >> 4) & 15;

                uint64_t a = regs[dst];
                uint64_t b = regs[src];
                uint64_t val;

                switch (aluop) {
                    case 0: val = a + b; break;
                    case 1: val = a - b; break;
                    case 2: val = a * b; break;
                    case 3: val = a % b; break;
                    case 4: val = a & b; break;
                    case 5: val = a | b; break;
                    case 6: val = a ^ b; break;
                    case 7: val = a >> b; break;
                }

                regs[dst] = val;
                pc += 2;
                TRACE("alu_%d r%d, r%d\n", aluop, dst, src);
                break;
            }

            // ST
            case 4: {
                uint8_t addr = rom[pc+1] & 15;
                uint8_t val = (rom[pc+1] >> 4) & 15;
                *(uint64_t *)(&ram[regs[addr]]) = regs[val];
                pc += 2;
                TRACE("st r%d, r%d\n", addr, val);
                break;
            }

            // LD
            case 5: {
                uint8_t addr = rom[pc+1] & 15;
                uint8_t val = (rom[pc+1] >> 4) & 15;
                regs[val] = *(uint64_t *)(&ram[regs[addr]]);
                pc += 2;
                TRACE("ld r%d, r%d\n", addr, val);
                break;
            }

            // LDM
            case 6: {
                uint8_t addr = rom[pc+1] & 15;
                uint8_t val = (rom[pc+1] >> 4) & 15;
                regs[val] = *(uint64_t *)(&rom[regs[addr]]);
                pc += 2;
                TRACE("ldm r%d, r%d\n", addr, val);
                break;
            }

            // JMP
            case 7: {
                uint64_t target = *(uint64_t *)(&rom[pc+1]);
                pc = target;
                TRACE("jmp 0x%lx\n", target);
                break;
            }

            // JR
            case 8: {
                uint8_t target = (rom[pc] >> 4) & 15;
                pc = regs[target];
                TRACE("jr r%d\n", target);
                break;
            }

            // JEQ
            case 9: {
                uint8_t v1 = rom[pc+1] & 15;
                uint8_t v2 = (rom[pc+1] >> 4) & 15;
                uint64_t target = *(uint64_t *)(&rom[pc+2]);
                pc = (regs[v1] == regs[v2] ? target : pc+10);
                TRACE("jeq r%d, r%d, 0x%lx\n", v1, v2, target);
                break;
            }

            // PUTV
            case 10: {
                uint8_t target = rom[pc+1] & 15;
                printf("r%d = 0x%lx\n", target, regs[target]);
                pc += 2;
                break;
            }

            default: {
                printf("Unknown instruction: %d\n", op);
                exit(-1);
            }
        }
    }

    return 0;
}

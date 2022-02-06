
all: breach breach.bin

breach: breach.c
	gcc -o breach breach.c
	strip --strip-all breach

breach.bin: breach.asm code assembler.py
	python3 assembler.py breach.asm breach.bin

code: code.asm
	nasm code.asm

clean:
	rm -rf breach breach.bin

